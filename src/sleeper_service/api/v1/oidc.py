"""Per-tenant OIDC client config (BUILD_PLAN § Admin UI & human auth).

Tenant admins register their IdP (Keycloak, Authentik, a corporate IdP —
anything speaking OIDC discovery); the UI login page then offers SSO for
that tenant alongside local auth, which always keeps working. The client
secret is encrypted at rest and never echoed back.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import OidcConfigOut, OidcConfigSet
from sleeper_service.api.v1.tenants import _get_visible_tenant
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_tenant_admin
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import OidcConfig
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/tenants/{tenant_id}/oidc", tags=["oidc"])


async def _gate(
    tenant_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal
) -> None:
    await _get_visible_tenant(tenant_id, db, principal)
    await require_tenant_admin(db, principal, tenant_id)


@router.put("", response_model=OidcConfigOut)
async def set_oidc_config(
    tenant_id: uuid.UUID,
    body: OidcConfigSet,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> OidcConfig:
    await _gate(tenant_id, db, principal)
    config = await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant_id))
    if config is None:
        config = OidcConfig(tenant_id=tenant_id)
        db.add(config)
    config.issuer = body.issuer.rstrip("/")
    config.client_id = body.client_id
    config.client_secret_enc = encrypt(body.client_secret)
    config.scopes = body.scopes
    await db.commit()
    await db.refresh(config)
    return config


@router.get("", response_model=OidcConfigOut)
async def get_oidc_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> OidcConfig:
    await _gate(tenant_id, db, principal)
    config = await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant_id))
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No OIDC config for this tenant")
    return config


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def delete_oidc_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _gate(tenant_id, db, principal)
    config = await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant_id))
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No OIDC config for this tenant")
    await db.delete(config)
    await db.commit()
