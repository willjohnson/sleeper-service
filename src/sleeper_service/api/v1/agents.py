import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import AgentCreate, AgentOut, AgentUpdate
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.db.models import Agent, Job, Team
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/agents", tags=["agents"])

# Learning governance (decided 2026-08-02): flipping these requires the team
# owner — editors manage everything else about an agent.
GOVERNED_OPTION_KEYS = ("memory", "learning", "memory_approval")


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
    if any(body.options.get(k) for k in GOVERNED_OPTION_KEYS):
        require_role(principal, team.id, Role.OWNER)
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
    include_archived: bool = False,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[Agent]:
    stmt = select(Agent).order_by(Agent.created_at)
    if not include_archived:
        stmt = stmt.where(Agent.archived_at.is_(None))
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
    if "options" in updates:
        old = agent.options or {}
        new = updates["options"] or {}
        if any(old.get(k) != new.get(k) for k in GOVERNED_OPTION_KEYS):
            require_role(principal, agent.team_id, Role.OWNER)
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
    # jobs.agent_id does not cascade, so this would fail in the database with
    # an IntegrityError. Refuse it here with an answer the caller can act on.
    jobs = await db.scalar(select(func.count()).select_from(Job).where(Job.agent_id == agent.id))
    if jobs:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Agent has {jobs} job(s) and cannot be deleted — archive it instead "
            f"(POST /v1/agents/{agent_id}/archive).",
        )
    await db.delete(agent)
    await db.commit()


@router.post("/{agent_id}/archive", response_model=AgentOut)
async def archive_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Agent:
    """Retire an agent without touching its history: it disappears from
    listings and refuses new work, while jobs, versions and evals stay."""
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    if agent.archived_at is None:
        agent.archived_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(agent)
    return agent


@router.post("/{agent_id}/restore", response_model=AgentOut)
async def restore_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Agent:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    if agent.archived_at is not None:
        agent.archived_at = None
        await db.commit()
        await db.refresh(agent)
    return agent


@router.get("/{agent_id}/memory")
async def get_agent_memory(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> dict:
    """Current memory document and version history (viewer+)."""
    from sleeper_service.api.v1.schemas import (
        AgentMemoryOut,
        MemoryVersionOut,
        MemoryVersionWithContentOut,
    )
    from sleeper_service.db.models import MemoryVersion
    from sleeper_service.runtime.memory import latest_memory

    await _get_visible_agent(agent_id, db, principal)
    current = await latest_memory(db, agent_id)
    versions = list(
        await db.scalars(
            select(MemoryVersion)
            .where(MemoryVersion.agent_id == agent_id)
            .order_by(MemoryVersion.version_no.desc())
        )
    )
    return AgentMemoryOut(
        current=MemoryVersionWithContentOut.model_validate(current) if current else None,
        versions=[MemoryVersionOut.model_validate(v) for v in versions],
    ).model_dump()
