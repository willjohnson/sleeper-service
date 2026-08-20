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
    Principal,
    UserPrincipal,
    get_principal,
)
from sleeper_service.auth.rbac import visible_team_ids
from sleeper_service.constants import TEXT_CONTENT_TYPES, KeyScope
from sleeper_service.db.models import File, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/files", tags=["files"])

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB

# Leading bytes → real type, for the formats a model reads natively.
_MAGIC: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),  # also docx/xlsx/pptx
]


def _looks_like_text(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return True
    try:
        text = sample.decode()
    except UnicodeDecodeError:
        return False
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r")
    return control / len(text) < 0.01


def sniff_content_type(data: bytes, declared: str) -> str:
    """Derive a file's content type from its bytes.

    The declared type is a security decision, not a display hint: the runner
    inlines (and therefore injection-screens) only text-typed files and hands
    everything else to the model as opaque BinaryContent. Trusting the client's
    multipart header would let anyone who can upload label injection text
    `application/pdf` and skip the screen entirely, while the identical bytes
    sent as `text/plain` are caught. So: real magic bytes win, text-looking
    bytes are treated as text, and the declared type is kept only when it
    doesn't contradict the content.
    """
    for magic, sniffed in _MAGIC:
        if data.startswith(magic):
            return sniffed
    if _looks_like_text(data):
        return declared if declared.startswith(TEXT_CONTENT_TYPES) else "text/plain"
    return declared


async def _check_tenant_access(
    db: AsyncSession, principal: Principal, tenant_id: uuid.UUID
) -> None:
    if isinstance(principal, UserPrincipal):
        if principal.is_superuser or await visible_team_ids(db, principal, tenant_id):
            return
    elif principal.scope == KeyScope.TENANT and principal.scope_id == tenant_id:
        # Files are tenant-scoped, so only a tenant-covering invoke key
        # matches the boundary. Narrower keys stay on the job surface
        # (submission within scope, results, feedback) and get no direct
        # file access — reading or writing any file in the tenant is not
        # theirs to do.
        return
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
async def upload_file(
    tenant_id: uuid.UUID,
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> File:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await _check_tenant_access(db, principal, tenant_id)

    # Reject on the rolled size before reading: read() pulls the whole
    # spooled body into memory, so a check that only runs afterwards cannot
    # prevent an oversized upload from exhausting it.
    if file.size is not None and file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds {MAX_FILE_SIZE} bytes",
        )
    data = await file.read()
    if len(data) > MAX_FILE_SIZE:  # backstop: size is None when unknown
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds {MAX_FILE_SIZE} bytes",
        )
    from pathlib import Path

    raw_name = Path(file.filename).name if file.filename else "upload"
    safe_name = raw_name or "upload"
    file_id = uuid.uuid4()
    object_key = f"{tenant_id}/payload/{file_id}/{safe_name}"
    content_type = sniff_content_type(data, file.content_type or "application/octet-stream")
    await storage.put_object(object_key, data, content_type)

    from sleeper_service.runtime.retention import file_expiry

    row = File(
        id=file_id,
        tenant_id=tenant_id,
        object_key=object_key,
        size=len(data),
        content_type=content_type,
        expires_at=file_expiry(tenant.settings or {}),
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
