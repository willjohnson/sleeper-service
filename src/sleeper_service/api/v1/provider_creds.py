"""Tenant-scoped provider API credentials (encrypted at rest).

Phase 1 keeps this to tenant scope; team/agent-scoped overrides come with the
spend-attribution work. Resolution at runtime: tenant credential, then
process environment (see runtime/providers.py).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import ProviderCredOut, ProviderCredSet
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_tenant_admin
from sleeper_service.constants import KeyScope
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import ProviderCred, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/tenants/{tenant_id}/provider-creds", tags=["provider-creds"])


async def _admin_gate(
    tenant_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal
) -> None:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await require_tenant_admin(db, principal, tenant_id)


@router.put("/{provider}", response_model=ProviderCredOut)
async def set_provider_cred(
    tenant_id: uuid.UUID,
    provider: str,
    body: ProviderCredSet,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> ProviderCred:
    await _admin_gate(tenant_id, db, principal)
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == KeyScope.TENANT,
            ProviderCred.scope_id == tenant_id,
            ProviderCred.provider == provider,
        )
    )
    if cred is None:
        cred = ProviderCred(
            scope=KeyScope.TENANT,
            scope_id=tenant_id,
            provider=provider,
            credentials_enc=encrypt(body.api_key),
        )
        db.add(cred)
    else:
        cred.credentials_enc = encrypt(body.api_key)
    await db.commit()
    await db.refresh(cred)
    return cred


@router.get("", response_model=list[ProviderCredOut])
async def list_provider_creds(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[ProviderCred]:
    await _admin_gate(tenant_id, db, principal)
    return list(
        await db.scalars(
            select(ProviderCred).where(
                ProviderCred.scope == KeyScope.TENANT,
                ProviderCred.scope_id == tenant_id,
            )
        )
    )


@router.delete("/{provider}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider_cred(
    tenant_id: uuid.UUID,
    provider: str,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _admin_gate(tenant_id, db, principal)
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == KeyScope.TENANT,
            ProviderCred.scope_id == tenant_id,
            ProviderCred.provider == provider,
        )
    )
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(cred)
    await db.commit()
