"""Payload file uploads (BUILD_PLAN § Files & external resources).

Files are tenant-scoped: any member of a team in the tenant (or a
tenant-covering invoke key) may upload and read. Jobs reference files by id.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service import storage
from sleeper_service.api.v1.schemas import FileOut
from sleeper_service.auth.principal import (
    InvokePrincipal,
    Principal,
    UserPrincipal,
    get_principal,
)
from sleeper_service.auth.rbac import visible_team_ids
from sleeper_service.constants import KeyScope
from sleeper_service.db.models import Agent, File, Team, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/files", tags=["files"])

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB


async def resolve_tenant_for_invoke(db: AsyncSession, p: InvokePrincipal) -> uuid.UUID | None:
    if p.scope == KeyScope.TENANT:
        return p.scope_id
    if p.scope == KeyScope.TEAM:
        team = await db.get(Team, p.scope_id)
        return team.tenant_id if team else None
    agent = await db.get(Agent, p.scope_id)
    return agent.tenant_id if agent else None


async def _check_tenant_access(
    db: AsyncSession, principal: Principal, tenant_id: uuid.UUID
) -> None:
    if isinstance(principal, UserPrincipal):
        if principal.is_superuser or await visible_team_ids(db, principal, tenant_id):
            return
    else:
        if await resolve_tenant_for_invoke(db, principal) == tenant_id:
            return
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
async def upload_file(
    tenant_id: uuid.UUID,
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> File:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await _check_tenant_access(db, principal, tenant_id)

    data = await file.read()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds {MAX_FILE_SIZE} bytes",
        )
    file_id = uuid.uuid4()
    object_key = f"{tenant_id}/payload/{file_id}/{file.filename or 'upload'}"
    content_type = file.content_type or "application/octet-stream"
    await storage.put_object(object_key, data, content_type)

    row = File(
        id=file_id,
        tenant_id=tenant_id,
        object_key=object_key,
        size=len(data),
        content_type=content_type,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/{file_id}", response_model=FileOut)
async def get_file(
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> File:
    row = await db.get(File, file_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await _check_tenant_access(db, principal, row.tenant_id)
    return row


@router.get("/{file_id}/content")
async def download_file(
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> Response:
    row = await db.get(File, file_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await _check_tenant_access(db, principal, row.tenant_id)
    data = await storage.get_object(row.object_key)
    return Response(content=data, media_type=row.content_type)
