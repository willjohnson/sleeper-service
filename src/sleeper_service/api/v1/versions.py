"""Agent versions: immutable snapshots, promotion, rollback, aliases.

Editors create versions; owners promote (repoint current_version_id — which
is also how rollback works). The first version of an agent auto-promotes so a
freshly configured agent is runnable. Version rows are never mutated.

Aliases (`dev`/`staging`/`prod` → version) are owner-managed named pointers;
job submissions may pin by alias and promotion = repointing, like current.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.agents import _get_visible_agent
from sleeper_service.api.v1.schemas import (
    ALIAS_PATTERN,
    AliasOut,
    AliasSet,
    PromoteRequest,
    VersionCreate,
    VersionOut,
)
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.db.models import Agent, AgentVersion, Model, VersionAlias
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/agents/{agent_id}", tags=["versions"])


async def resolve_model(db: AsyncSession, model_ref: str) -> Model:
    """Accept a registry model_string ("anthropic:claude-sonnet-5") or "provider/name"."""
    model = await db.scalar(select(Model).where(Model.model_string == model_ref))
    if model is None and "/" in model_ref:
        provider, _, name = model_ref.partition("/")
        model = await db.scalar(select(Model).where(Model.provider == provider, Model.name == name))
    if model is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unknown model {model_ref!r} — register it in the models registry first",
        )
    return model


@router.post("/versions", response_model=VersionOut, status_code=status.HTTP_201_CREATED)
async def create_version(
    agent_id: uuid.UUID,
    body: VersionCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> AgentVersion:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.EDITOR)
    model = await resolve_model(db, body.model)

    next_no = (
        await db.scalar(
            select(func.coalesce(func.max(AgentVersion.version_no), 0)).where(
                AgentVersion.agent_id == agent_id
            )
        )
        + 1
    )
    version = AgentVersion(
        agent_id=agent_id,
        version_no=next_no,
        prompt=body.prompt,
        model_id=model.id,
        params=body.params,
        max_iterations=body.max_iterations,
        timeout_s=body.timeout_s,
        tool_grants=body.tool_grants,
        data_store_grants=body.data_store_grants,
        input_schema=body.input_schema,
        output_schema=body.output_schema,
        created_by=principal.user.id,
    )
    db.add(version)
    await db.flush()
    if agent.current_version_id is None:
        agent.current_version_id = version.id
    await db.commit()
    await db.refresh(version)
    return version


@router.get("/versions", response_model=list[VersionOut])
async def list_versions(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[AgentVersion]:
    await _get_visible_agent(agent_id, db, principal)
    return list(
        await db.scalars(
            select(AgentVersion)
            .where(AgentVersion.agent_id == agent_id)
            .order_by(AgentVersion.version_no)
        )
    )


@router.get("/versions/{version_no}", response_model=VersionOut)
async def get_version(
    agent_id: uuid.UUID,
    version_no: int,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> AgentVersion:
    await _get_visible_agent(agent_id, db, principal)
    version = await db.scalar(
        select(AgentVersion).where(
            AgentVersion.agent_id == agent_id, AgentVersion.version_no == version_no
        )
    )
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return version


@router.post("/promote", response_model=VersionOut)
async def promote_version(
    agent_id: uuid.UUID,
    body: PromoteRequest,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> AgentVersion:
    agent: Agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    version = await db.scalar(
        select(AgentVersion).where(
            AgentVersion.agent_id == agent_id,
            AgentVersion.version_no == body.version_no,
        )
    )
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    agent.current_version_id = version.id
    await db.commit()
    await db.refresh(version)
    return version


# --- Aliases ---


@router.put("/aliases/{alias}", response_model=AliasOut)
async def set_alias(
    agent_id: uuid.UUID,
    body: AliasSet,
    alias: str = Path(pattern=ALIAS_PATTERN),
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> AliasOut:
    """Create or repoint an alias (owner) — promotion/rollback for aliases."""
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    version = await db.scalar(
        select(AgentVersion).where(
            AgentVersion.agent_id == agent_id, AgentVersion.version_no == body.version_no
        )
    )
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")

    row = await db.get(VersionAlias, (agent_id, alias))
    if row is None:
        row = VersionAlias(agent_id=agent_id, alias=alias, agent_version_id=version.id)
        db.add(row)
    else:
        row.agent_version_id = version.id
    await db.commit()
    await db.refresh(row)
    return AliasOut(
        agent_id=agent_id,
        alias=alias,
        agent_version_id=version.id,
        version_no=version.version_no,
        created_at=row.created_at,
    )


@router.get("/aliases", response_model=list[AliasOut])
async def list_aliases(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[AliasOut]:
    await _get_visible_agent(agent_id, db, principal)
    rows = (
        await db.execute(
            select(VersionAlias, AgentVersion.version_no)
            .join(AgentVersion, VersionAlias.agent_version_id == AgentVersion.id)
            .where(VersionAlias.agent_id == agent_id)
            .order_by(VersionAlias.alias)
        )
    ).all()
    return [
        AliasOut(
            agent_id=row.agent_id,
            alias=row.alias,
            agent_version_id=row.agent_version_id,
            version_no=vno,
            created_at=row.created_at,
        )
        for row, vno in rows
    ]


@router.delete("/aliases/{alias}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alias(
    agent_id: uuid.UUID,
    alias: str,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    row = await db.get(VersionAlias, (agent_id, alias))
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(row)
    await db.commit()
