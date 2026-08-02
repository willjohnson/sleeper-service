import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import AgentCreate, AgentOut, AgentUpdate
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.db.models import Agent, Team
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("", response_model=AgentOut, status_code=status.HTTP_201_CREATED)
async def create_agent(
    body: AgentCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Agent:
    team = await db.get(Team, body.team_id)
    if team is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    require_role(principal, team.id, Role.EDITOR)
    if await db.scalar(
        select(Agent).where(Agent.tenant_id == team.tenant_id, Agent.name == body.name)
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "Agent name already exists in this tenant")
    agent = Agent(
        tenant_id=team.tenant_id,
        team_id=team.id,
        name=body.name,
        description=body.description,
        spending_limit=body.spending_limit,
        options=body.options,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.get("", response_model=list[AgentOut])
async def list_agents(
    tenant_id: uuid.UUID | None = None,
    team_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[Agent]:
    stmt = select(Agent).order_by(Agent.created_at)
    if tenant_id is not None:
        stmt = stmt.where(Agent.tenant_id == tenant_id)
    if team_id is not None:
        stmt = stmt.where(Agent.team_id == team_id)
    if not principal.is_superuser:
        visible = list(principal.roles)
        if not visible:
            return []
        stmt = stmt.where(Agent.team_id.in_(visible))
    return list(await db.scalars(stmt))


async def _get_visible_agent(
    agent_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal
) -> Agent:
    agent = await db.get(Agent, agent_id)
    if agent is None or not (principal.is_superuser or agent.team_id in principal.roles):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return agent


@router.get("/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Agent:
    return await _get_visible_agent(agent_id, db, principal)


@router.patch("/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: uuid.UUID,
    body: AgentUpdate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Agent:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.EDITOR)
    updates = body.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] != agent.name:
        dup = await db.scalar(
            select(Agent).where(Agent.tenant_id == agent.tenant_id, Agent.name == updates["name"])
        )
        if dup:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Agent name already exists in this tenant"
            )
    for field, value in updates.items():
        setattr(agent, field, value)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.get("/{agent_id}/spend")
async def get_agent_spend(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> dict:
    from sleeper_service.api.v1.schemas import SpendOut
    from sleeper_service.runtime import spending

    agent = await _get_visible_agent(agent_id, db, principal)
    spend = await spending.month_spend(db, agent_id)
    return SpendOut(
        agent_id=agent_id,
        month_start=spending.month_start(),
        spend=spend,
        spending_limit=agent.spending_limit,
    ).model_dump()


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    await db.delete(agent)
    await db.commit()
