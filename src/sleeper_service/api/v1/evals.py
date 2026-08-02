"""Eval cases and runs (BUILD_PLAN § Eval design).

Editors manage cases and start runs (RBAC matrix: "manage eval cases");
viewers read. Two completed runs side by side = branch comparison; the
winner is promoted via the existing /promote endpoint.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.agents import _get_visible_agent
from sleeper_service.api.v1.schemas import (
    EvalCaseCreate,
    EvalCaseOut,
    EvalRunCreate,
    EvalRunOut,
)
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.db.models import AgentVersion, EvalCase, EvalRun
from sleeper_service.db.session import get_db
from sleeper_service.queue import get_pool
from sleeper_service.runtime.evals import validate_checks

router = APIRouter(prefix="/agents/{agent_id}", tags=["evals"])


@router.post("/eval-cases", response_model=EvalCaseOut, status_code=status.HTTP_201_CREATED)
async def create_eval_case(
    agent_id: uuid.UUID,
    body: EvalCaseCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> EvalCase:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.EDITOR)
    error = validate_checks(body.checks)
    if error is not None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, error)
    dup = await db.scalar(
        select(EvalCase).where(EvalCase.agent_id == agent_id, EvalCase.name == body.name)
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "Case name already exists")
    case = EvalCase(
        agent_id=agent_id,
        name=body.name,
        input=body.input.model_dump(mode="json"),
        checks=body.checks,
        created_by=principal.user.id,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return case


@router.get("/eval-cases", response_model=list[EvalCaseOut])
async def list_eval_cases(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[EvalCase]:
    await _get_visible_agent(agent_id, db, principal)
    return list(
        await db.scalars(
            select(EvalCase).where(EvalCase.agent_id == agent_id).order_by(EvalCase.name)
        )
    )


@router.delete("/eval-cases/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_eval_case(
    agent_id: uuid.UUID,
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.EDITOR)
    case = await db.get(EvalCase, case_id)
    if case is None or case.agent_id != agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(case)
    await db.commit()


@router.post("/eval-runs", response_model=EvalRunOut, status_code=status.HTTP_202_ACCEPTED)
async def start_eval_run(
    agent_id: uuid.UUID,
    body: EvalRunCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> EvalRun:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.EDITOR)

    if body.agent_version_id is not None:
        version = await db.get(AgentVersion, body.agent_version_id)
        if version is None or version.agent_id != agent_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown version")
    elif body.version_no is not None:
        version = await db.scalar(
            select(AgentVersion).where(
                AgentVersion.agent_id == agent_id,
                AgentVersion.version_no == body.version_no,
            )
        )
        if version is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown version")
    else:
        if agent.current_version_id is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Agent has no versions yet")
        version = await db.get(AgentVersion, agent.current_version_id)

    case_count = await db.scalar(select(EvalCase.id).where(EvalCase.agent_id == agent_id).limit(1))
    if case_count is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Agent has no eval cases yet")

    run = EvalRun(
        agent_id=agent_id,
        agent_version_id=version.id,
        created_by=principal.user.id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    pool = await get_pool()
    await pool.enqueue_job("run_eval", str(run.id))
    return run


@router.get("/eval-runs", response_model=list[EvalRunOut])
async def list_eval_runs(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[EvalRun]:
    await _get_visible_agent(agent_id, db, principal)
    return list(
        await db.scalars(
            select(EvalRun).where(EvalRun.agent_id == agent_id).order_by(EvalRun.created_at.desc())
        )
    )


@router.get("/eval-runs/{run_id}", response_model=EvalRunOut)
async def get_eval_run(
    agent_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> EvalRun:
    await _get_visible_agent(agent_id, db, principal)
    run = await db.get(EvalRun, run_id)
    if run is None or run.agent_id != agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return run
