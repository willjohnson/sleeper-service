"""Job submission and inspection (BUILD_PLAN § Job lifecycle).

Async by default: 202 + job id, result later via callback and GET /jobs/{id}.
?sync=true runs inline for fast agents. Both key kinds may submit: invoke keys
within their scope, user keys with editor+ on the agent's team (viewers read).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import JobEventOut, JobOut, JobSubmit
from sleeper_service.auth.principal import (
    InvokePrincipal,
    Principal,
    UserPrincipal,
    get_principal,
)
from sleeper_service.auth.rbac import has_role
from sleeper_service.constants import KeyScope, Role
from sleeper_service.db.models import Agent, AgentVersion, File, Job, JobEvent
from sleeper_service.db.session import get_db
from sleeper_service.queue import get_pool

router = APIRouter(tags=["jobs"])


def _invoke_covers(p: InvokePrincipal, agent: Agent) -> bool:
    return (
        (p.scope == KeyScope.AGENT and p.scope_id == agent.id)
        or (p.scope == KeyScope.TEAM and p.scope_id == agent.team_id)
        or (p.scope == KeyScope.TENANT and p.scope_id == agent.tenant_id)
    )


async def _get_agent_for(
    db: AsyncSession, principal: Principal, agent_id: uuid.UUID, *, submit: bool
) -> Agent:
    agent = await db.get(Agent, agent_id)
    visible = agent is not None and (
        _invoke_covers(principal, agent)
        if isinstance(principal, InvokePrincipal)
        else principal.is_superuser or agent.team_id in principal.roles
    )
    if not visible:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if (
        submit
        and isinstance(principal, UserPrincipal)
        and not has_role(principal, agent.team_id, Role.EDITOR)
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Submitting jobs requires editor role"
        )
    return agent


async def _resolve_version(
    db: AsyncSession, agent: Agent, body: JobSubmit
) -> AgentVersion:
    if body.agent_version_id is not None:
        version = await db.get(AgentVersion, body.agent_version_id)
        if version is None or version.agent_id != agent.id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown version")
        return version
    if body.version_no is not None:
        version = await db.scalar(
            select(AgentVersion).where(
                AgentVersion.agent_id == agent.id,
                AgentVersion.version_no == body.version_no,
            )
        )
        if version is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown version")
        return version
    if agent.current_version_id is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Agent has no versions yet — create one first"
        )
    return await db.get(AgentVersion, agent.current_version_id)


@router.post(
    "/agents/{agent_id}/jobs", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED
)
async def submit_job(
    agent_id: uuid.UUID,
    body: JobSubmit,
    sync: bool = False,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> Job:
    agent = await _get_agent_for(db, principal, agent_id, submit=True)
    version = await _resolve_version(db, agent, body)

    for file_id in body.context.files:
        file = await db.get(File, file_id)
        if file is None or file.tenant_id != agent.tenant_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown file {file_id}"
            )

    if body.idempotency_key is not None:
        existing = await db.scalar(
            select(Job).where(
                Job.agent_id == agent.id, Job.idempotency_key == body.idempotency_key
            )
        )
        if existing is not None:
            return existing

    job = Job(
        agent_id=agent.id,
        agent_version_id=version.id,
        payload=body.context.model_dump(mode="json"),
        callback_url=body.callback_url,
        user_ctx=body.user_ctx,
        idempotency_key=body.idempotency_key,
    )
    db.add(job)
    try:
        await db.flush()
    except IntegrityError:
        # Concurrent submit with the same idempotency key: return the winner.
        await db.rollback()
        existing = await db.scalar(
            select(Job).where(
                Job.agent_id == agent.id, Job.idempotency_key == body.idempotency_key
            )
        )
        if existing is not None:
            return existing
        raise
    db.add(JobEvent(job_id=job.id, type="submitted", data={"sync": sync}))
    await db.commit()
    await db.refresh(job)

    if sync:
        from sleeper_service.runtime.runner import TransientJobError, execute_job, mark_job

        try:
            await execute_job(job.id, sync_cap=True)
        except TransientJobError as e:
            # No retry budget in the request/response path — fail it now.
            await mark_job(job.id, "failed", f"transient provider error: {e}")
        await db.refresh(job)
        if job.callback_url:
            pool = await get_pool()
            await pool.enqueue_job("deliver_callback", str(job.id))
        return job

    pool = await get_pool()
    await pool.enqueue_job("run_job", str(job.id))
    return job


async def _get_job_for(
    db: AsyncSession, principal: Principal, job_id: uuid.UUID
) -> Job:
    job = await db.get(Job, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await _get_agent_for(db, principal, job.agent_id, submit=False)
    return job


@router.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> Job:
    return await _get_job_for(db, principal, job_id)


@router.get("/jobs/{job_id}/events", response_model=list[JobEventOut])
async def get_job_events(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> list[JobEvent]:
    await _get_job_for(db, principal, job_id)
    return list(
        await db.scalars(
            select(JobEvent).where(JobEvent.job_id == job_id).order_by(JobEvent.id)
        )
    )
