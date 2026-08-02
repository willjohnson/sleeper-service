"""Provider API credentials (encrypted at rest), scoped tenant/team/agent.

Runtime resolution walks agent → team → tenant → process environment
(runtime/providers.resolve_api_key), so a narrower credential overrides a
broader one — provider spend maps to the vendor bill at the right level.
Tenant creds are managed by tenant admins; team and agent creds by the
owning team's owner.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.agents import _get_visible_agent
from sleeper_service.api.v1.schemas import ProviderCredOut, ProviderCredSet
from sleeper_service.api.v1.teams import _get_visible_team
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role, require_tenant_admin
from sleeper_service.constants import KeyScope, Role
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import ProviderCred, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(tags=["provider-creds"])


async def _gate(
    db: AsyncSession, principal: UserPrincipal, scope: KeyScope, scope_id: uuid.UUID
) -> None:
    """404 for invisible targets, 403 below the managing role per scope."""
    if scope == KeyScope.TENANT:
        if await db.get(Tenant, scope_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        await require_tenant_admin(db, principal, scope_id)
    elif scope == KeyScope.TEAM:
        team = await _get_visible_team(scope_id, db, principal)
        require_role(principal, team.id, Role.OWNER)
    else:
        agent = await _get_visible_agent(scope_id, db, principal)
        require_role(principal, agent.team_id, Role.OWNER)


async def _set(
    db: AsyncSession,
    principal: UserPrincipal,
    scope: KeyScope,
    scope_id: uuid.UUID,
    provider: str,
    body: ProviderCredSet,
) -> ProviderCred:
    await _gate(db, principal, scope, scope_id)
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == scope,
            ProviderCred.scope_id == scope_id,
            ProviderCred.provider == provider,
        )
    )
    if cred is None:
        cred = ProviderCred(
            scope=scope,
            scope_id=scope_id,
            provider=provider,
            credentials_enc=encrypt(body.api_key),
        )
        db.add(cred)
    else:
        cred.credentials_enc = encrypt(body.api_key)
    await db.commit()
    await db.refresh(cred)
    return cred


async def _list(
    db: AsyncSession, principal: UserPrincipal, scope: KeyScope, scope_id: uuid.UUID
) -> list[ProviderCred]:
    await _gate(db, principal, scope, scope_id)
    return list(
        await db.scalars(
            select(ProviderCred).where(
                ProviderCred.scope == scope, ProviderCred.scope_id == scope_id
            )
        )
    )


async def _delete(
    db: AsyncSession,
    principal: UserPrincipal,
    scope: KeyScope,
    scope_id: uuid.UUID,
    provider: str,
) -> None:
    await _gate(db, principal, scope, scope_id)
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == scope,
            ProviderCred.scope_id == scope_id,
            ProviderCred.provider == provider,
        )
    )
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(cred)
    await db.commit()


# --- Tenant scope ---


@router.put("/tenants/{tenant_id}/provider-creds/{provider}", response_model=ProviderCredOut)
async def set_tenant_provider_cred(
    tenant_id: uuid.UUID,
    provider: str,
    body: ProviderCredSet,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> ProviderCred:
    return await _set(db, principal, KeyScope.TENANT, tenant_id, provider, body)


@router.get("/tenants/{tenant_id}/provider-creds", response_model=list[ProviderCredOut])
async def list_tenant_provider_creds(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[ProviderCred]:
    return await _list(db, principal, KeyScope.TENANT, tenant_id)


@router.delete(
    "/tenants/{tenant_id}/provider-creds/{provider}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_tenant_provider_cred(
    tenant_id: uuid.UUID,
    provider: str,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _delete(db, principal, KeyScope.TENANT, tenant_id, provider)


# --- Team scope ---


@router.put("/teams/{team_id}/provider-creds/{provider}", response_model=ProviderCredOut)
async def set_team_provider_cred(
    team_id: uuid.UUID,
    provider: str,
    body: ProviderCredSet,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> ProviderCred:
    return await _set(db, principal, KeyScope.TEAM, team_id, provider, body)


@router.get("/teams/{team_id}/provider-creds", response_model=list[ProviderCredOut])
async def list_team_provider_creds(
    team_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[ProviderCred]:
    return await _list(db, principal, KeyScope.TEAM, team_id)


@router.delete("/teams/{team_id}/provider-creds/{provider}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team_provider_cred(
    team_id: uuid.UUID,
    provider: str,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _delete(db, principal, KeyScope.TEAM, team_id, provider)


# --- Agent scope ---


@router.put("/agents/{agent_id}/provider-creds/{provider}", response_model=ProviderCredOut)
async def set_agent_provider_cred(
    agent_id: uuid.UUID,
    provider: str,
    body: ProviderCredSet,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> ProviderCred:
    return await _set(db, principal, KeyScope.AGENT, agent_id, provider, body)


@router.get("/agents/{agent_id}/provider-creds", response_model=list[ProviderCredOut])
async def list_agent_provider_creds(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[ProviderCred]:
    return await _list(db, principal, KeyScope.AGENT, agent_id)


@router.delete(
    "/agents/{agent_id}/provider-creds/{provider}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_agent_provider_cred(
    agent_id: uuid.UUID,
    provider: str,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _delete(db, principal, KeyScope.AGENT, agent_id, provider)
