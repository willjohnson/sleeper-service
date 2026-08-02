"""Team-scoped RBAC checks (BUILD_PLAN § RBAC matrix).

Roles live on team_members only. Superusers pass every check (instance
admin, created by `sleeper init`). Tenant-level administration is defined as
owning the tenant's org-wide team.

404 vs 403: a principal with no relationship to a resource gets 404 (the
resource's existence is not disclosed); a principal who can see it but lacks
the role gets 403.
"""

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.auth.principal import UserPrincipal
from sleeper_service.constants import ROLE_RANK, Role
from sleeper_service.db.models import Team


def has_role(principal: UserPrincipal, team_id: uuid.UUID, min_role: Role) -> bool:
    if principal.is_superuser:
        return True
    role = principal.roles.get(team_id)
    return role is not None and ROLE_RANK[role] >= ROLE_RANK[min_role]


def require_role(principal: UserPrincipal, team_id: uuid.UUID, min_role: Role) -> None:
    if has_role(principal, team_id, min_role):
        return
    if principal.roles.get(team_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Requires {min_role} role on this team",
    )


async def visible_team_ids(
    db: AsyncSession, principal: UserPrincipal, tenant_id: uuid.UUID
) -> list[uuid.UUID]:
    """Teams in a tenant the principal can read (any role; superuser: all)."""
    stmt = select(Team.id).where(Team.tenant_id == tenant_id)
    all_ids = list(await db.scalars(stmt))
    if principal.is_superuser:
        return all_ids
    return [tid for tid in all_ids if tid in principal.roles]


async def is_tenant_admin(db: AsyncSession, principal: UserPrincipal, tenant_id: uuid.UUID) -> bool:
    """Tenant admin = superuser or owner of the tenant's org-wide team."""
    if principal.is_superuser:
        return True
    org_team_id = await db.scalar(
        select(Team.id).where(Team.tenant_id == tenant_id, Team.is_org_team.is_(True))
    )
    return org_team_id is not None and principal.roles.get(org_team_id) == Role.OWNER


async def require_tenant_admin(
    db: AsyncSession, principal: UserPrincipal, tenant_id: uuid.UUID
) -> None:
    if await is_tenant_admin(db, principal, tenant_id):
        return
    if not any(True for _ in await visible_team_ids(db, principal, tenant_id)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Requires tenant admin (owner of the org-wide team)",
    )
