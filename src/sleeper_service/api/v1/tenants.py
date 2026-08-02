import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import TenantCreate, TenantOut, TenantUpdate
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_tenant_admin, visible_team_ids
from sleeper_service.db.models import Team, Tenant
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.post("", response_model=TenantOut, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    body: TenantCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Tenant:
    if not principal.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only superusers create tenants")
    if await db.scalar(select(Tenant).where(Tenant.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Tenant name already exists")
    tenant = Tenant(name=body.name, system_prompt=body.system_prompt)
    db.add(tenant)
    await db.flush()
    # Every tenant is born with its org-wide team (BUILD_PLAN seed).
    db.add(Team(tenant_id=tenant.id, name="org", is_org_team=True))
    await db.commit()
    await db.refresh(tenant)
    return tenant


@router.get("", response_model=list[TenantOut])
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[Tenant]:
    if principal.is_superuser:
        return list(await db.scalars(select(Tenant).order_by(Tenant.created_at)))
    team_ids = list(principal.roles)
    if not team_ids:
        return []
    stmt = (
        select(Tenant)
        .join(Team, Team.tenant_id == Tenant.id)
        .where(Team.id.in_(team_ids))
        .distinct()
        .order_by(Tenant.created_at)
    )
    return list(await db.scalars(stmt))


async def _get_visible_tenant(
    tenant_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal
) -> Tenant:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None or (
        not principal.is_superuser and not await visible_team_ids(db, principal, tenant_id)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return tenant


@router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Tenant:
    return await _get_visible_tenant(tenant_id, db, principal)


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant(
    tenant_id: uuid.UUID,
    body: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Tenant:
    tenant = await _get_visible_tenant(tenant_id, db, principal)
    await require_tenant_admin(db, principal, tenant_id)
    if body.system_prompt is not None:
        tenant.system_prompt = body.system_prompt
    if body.settings is not None:
        from sleeper_service.runtime.hooks import validate_hooks_settings

        hooks_error = validate_hooks_settings(body.settings)
        if hooks_error is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, hooks_error)
        tenant.settings = body.settings
    await db.commit()
    await db.refresh(tenant)
    return tenant
