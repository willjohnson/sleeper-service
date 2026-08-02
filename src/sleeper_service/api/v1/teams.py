import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import MemberOut, MemberSet, TeamCreate, TeamOut
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role, require_tenant_admin, visible_team_ids
from sleeper_service.constants import Role
from sleeper_service.db.models import Team, TeamMember, Tenant, User
from sleeper_service.db.session import get_db

router = APIRouter(tags=["teams"])


@router.post(
    "/tenants/{tenant_id}/teams",
    response_model=TeamOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_team(
    tenant_id: uuid.UUID,
    body: TeamCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Team:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await require_tenant_admin(db, principal, tenant_id)
    if await db.scalar(select(Team).where(Team.tenant_id == tenant_id, Team.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Team name already exists")

    owner_id = body.owner_user_id or principal.user.id
    if await db.get(User, owner_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Owner user not found")

    team = Team(tenant_id=tenant_id, name=body.name)
    db.add(team)
    await db.flush()
    db.add(TeamMember(user_id=owner_id, team_id=team.id, role=Role.OWNER))
    await db.commit()
    await db.refresh(team)
    return team


@router.get("/tenants/{tenant_id}/teams", response_model=list[TeamOut])
async def list_teams(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[Team]:
    team_ids = await visible_team_ids(db, principal, tenant_id)
    if not team_ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    stmt = select(Team).where(Team.id.in_(team_ids)).order_by(Team.created_at)
    return list(await db.scalars(stmt))


async def _get_visible_team(team_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal) -> Team:
    team = await db.get(Team, team_id)
    if team is None or not (principal.is_superuser or team.id in principal.roles):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return team


@router.get("/teams/{team_id}", response_model=TeamOut)
async def get_team(
    team_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Team:
    return await _get_visible_team(team_id, db, principal)


@router.get("/teams/{team_id}/members", response_model=list[MemberOut])
async def list_members(
    team_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[TeamMember]:
    await _get_visible_team(team_id, db, principal)
    return list(await db.scalars(select(TeamMember).where(TeamMember.team_id == team_id)))


@router.put("/teams/{team_id}/members/{user_id}", response_model=MemberOut)
async def set_member(
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    body: MemberSet,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> TeamMember:
    if await db.get(Team, team_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    require_role(principal, team_id, Role.OWNER)
    if await db.get(User, user_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "User not found")

    member = await db.get(TeamMember, (user_id, team_id))
    if member is None:
        member = TeamMember(user_id=user_id, team_id=team_id, role=body.role)
        db.add(member)
    else:
        if member.role == Role.OWNER and body.role != Role.OWNER:
            await _forbid_removing_last_owner(db, team_id)
        member.role = body.role
    await db.commit()
    return member


@router.delete("/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    if await db.get(Team, team_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    require_role(principal, team_id, Role.OWNER)
    member = await db.get(TeamMember, (user_id, team_id))
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if member.role == Role.OWNER:
        await _forbid_removing_last_owner(db, team_id)
    await db.delete(member)
    await db.commit()


async def _forbid_removing_last_owner(db: AsyncSession, team_id: uuid.UUID) -> None:
    owner_count = await db.scalar(
        select(func.count())
        .select_from(TeamMember)
        .where(TeamMember.team_id == team_id, TeamMember.role == Role.OWNER)
    )
    if owner_count <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Every team must keep at least one owner")
