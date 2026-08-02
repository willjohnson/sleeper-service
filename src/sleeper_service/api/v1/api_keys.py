"""Invoke-key management (data-plane credentials).

User keys are managed under /users/{id}/keys; this router covers invoke keys,
which grant only job submission / result reads / feedback within their scope.
Issuing one requires administrative rights over the scope: team scope — team
owner; agent scope — owner of the agent's team; tenant scope — tenant admin.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import ApiKeyOut, ApiKeyWithSecretOut, InvokeKeyCreate
from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import is_tenant_admin, require_role
from sleeper_service.constants import KeyKind, KeyScope, Role
from sleeper_service.db.models import Agent, ApiKey, Team, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


async def _require_scope_admin(
    db: AsyncSession, principal: UserPrincipal, scope: KeyScope, scope_id: uuid.UUID
) -> None:
    if scope == KeyScope.TENANT:
        if await db.get(Tenant, scope_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        if not await is_tenant_admin(db, principal, scope_id):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "Requires tenant admin for tenant-scoped keys"
            )
    elif scope == KeyScope.TEAM:
        if await db.get(Team, scope_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        require_role(principal, scope_id, Role.OWNER)
    elif scope == KeyScope.AGENT:
        agent = await db.get(Agent, scope_id)
        if agent is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        require_role(principal, agent.team_id, Role.OWNER)


@router.post("/invoke", response_model=ApiKeyWithSecretOut, status_code=status.HTTP_201_CREATED)
async def create_invoke_key(
    body: InvokeKeyCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> ApiKeyWithSecretOut:
    await _require_scope_admin(db, principal, body.scope, body.scope_id)
    plaintext, key_hash = generate_key(KeyKind.INVOKE)
    key = ApiKey(
        kind=KeyKind.INVOKE,
        scope=body.scope,
        scope_id=body.scope_id,
        key_hash=key_hash,
        name=body.name,
        rate_limit=body.rate_limit,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return ApiKeyWithSecretOut(
        **{f: getattr(key, f) for f in ApiKeyOut.model_fields}, api_key=plaintext
    )


@router.get("", response_model=list[ApiKeyOut])
async def list_invoke_keys(
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[ApiKey]:
    keys = list(
        await db.scalars(
            select(ApiKey).where(ApiKey.kind == KeyKind.INVOKE).order_by(ApiKey.created_at)
        )
    )
    if principal.is_superuser:
        return keys
    visible = []
    for key in keys:
        try:
            await _require_scope_admin(db, principal, KeyScope(key.scope), key.scope_id)
        except HTTPException:
            continue
        visible.append(key)
    return visible


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invoke_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    key = await db.get(ApiKey, key_id)
    if key is None or key.kind != KeyKind.INVOKE:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await _require_scope_admin(db, principal, KeyScope(key.scope), key.scope_id)
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
        await db.commit()
