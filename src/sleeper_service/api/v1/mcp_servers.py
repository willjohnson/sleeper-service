"""MCP server registry (BUILD_PLAN § Stack): tenant admin manages; agent
versions reference servers by name/id in tool_grants."""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import McpServerCreate, McpServerOut
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_tenant_admin, visible_team_ids
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import McpServer, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/tenants/{tenant_id}/mcp-servers", tags=["mcp-servers"])


async def _gate(
    tenant_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal, *, admin: bool
) -> None:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if admin:
        await require_tenant_admin(db, principal, tenant_id)
    elif not (principal.is_superuser or await visible_team_ids(db, principal, tenant_id)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


@router.post("", response_model=McpServerOut, status_code=status.HTTP_201_CREATED)
async def create_mcp_server(
    tenant_id: uuid.UUID,
    body: McpServerCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> McpServer:
    await _gate(tenant_id, db, principal, admin=True)
    if body.transport == "stdio" and not principal.is_superuser:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only instance superusers may register stdio MCP servers",
        )
    dup = await db.scalar(
        select(McpServer).where(McpServer.tenant_id == tenant_id, McpServer.name == body.name)
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "MCP server name already exists")
    server = McpServer(
        tenant_id=tenant_id,
        name=body.name,
        endpoint=body.endpoint,
        transport=body.transport,
        credentials_enc=encrypt(json.dumps(body.credentials)) if body.credentials else None,
    )
    db.add(server)
    await db.commit()
    await db.refresh(server)
    return server


@router.get("", response_model=list[McpServerOut])
async def list_mcp_servers(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[McpServer]:
    await _gate(tenant_id, db, principal, admin=False)
    return list(
        await db.scalars(
            select(McpServer).where(McpServer.tenant_id == tenant_id).order_by(McpServer.name)
        )
    )


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp_server(
    tenant_id: uuid.UUID,
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _gate(tenant_id, db, principal, admin=True)
    server = await db.get(McpServer, server_id)
    if server is None or server.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(server)
    await db.commit()
