"""Job submission and inspection (BUILD_PLAN § Job lifecycle).

Async by default: 202 + job id, result later via callback and GET /jobs/{id}.
?sync=true runs inline for fast agents. Both key kinds may submit: invoke keys
within their scope, user keys with editor+ on the agent's team (viewers read).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import JobEventOut, JobOut, JobSubmit, JobTreeOut
from sleeper_service.auth.principal import (
    InvokePrincipal,
    Principal,
    UserPrincipal,
    get_principal,
)
from sleeper_service.auth.rbac import has_role
from sleeper_service.constants import KeyScope, Role
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    File,
    Job,
    JobEvent,
    Tenant,
    VersionAlias,
)
from sleeper_service.db.session import get_db
from sleeper_service.queue import get_pool
from sleeper_service.runtime import links, spending
from sleeper_service.runtime.outbound import OutboundUrlError, validate_callback_url

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
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Submitting jobs requires editor role")
    return agent


async def _resolve_version(db: AsyncSession, agent: Agent, body: JobSubmit) -> AgentVersion:
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
    if body.alias is not None:
        row = await db.get(VersionAlias, (agent.id, body.alias))
        if row is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown alias")
        return await db.get(AgentVersion, row.agent_version_id)
    return await _resolve_version_current(db, agent)


async def _resolve_version_current(db: AsyncSession, agent: Agent) -> AgentVersion:
    if agent.current_version_id is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Agent has no versions yet — create one first"
        )
    return await db.get(AgentVersion, agent.current_version_id)


async def create_job(
    db: AsyncSession,
    agent: Agent,
    version: AgentVersion,
    *,
    context: dict,
    callback_url: str | None = None,
    user_ctx: dict | None = None,
    auth_ctx: dict | None = None,
    idempotency_key: str | None = None,
    sync: bool = False,
) -> tuple[Job, bool]:
    """Create (or dedupe) a job and enqueue it unless sync/refused.

    Returns (job, existed): existed=True means the idempotency key matched a
    prior submission and no new job was created. Shared by direct submission
    and event-source ingress.
    """
    if agent.archived_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Agent {agent.name!r} is archived and cannot take new work"
        )
    if idempotency_key is not None:
        existing = await db.scalar(
            select(Job).where(Job.agent_id == agent.id, Job.idempotency_key == idempotency_key)
        )
        if existing is not None:
            return existing, True

    job = Job(
        agent_id=agent.id,
        agent_version_id=version.id,
        payload=context,
        callback_url=callback_url,
        user_ctx=user_ctx,
        auth_ctx=auth_ctx,
        idempotency_key=idempotency_key,
    )
    db.add(job)
    try:
        await db.flush()
    except IntegrityError:
        # Concurrent submit with the same idempotency key: return the winner.
        await db.rollback()
        existing = await db.scalar(
            select(Job).where(Job.agent_id == agent.id, Job.idempotency_key == idempotency_key)
        )
        if existing is not None:
            return existing, True
        raise
    db.add(JobEvent(job_id=job.id, type="submitted", data={"sync": sync}))
    await db.commit()
    await db.refresh(job)

    # Budget pre-flight: refuse (auditable row, no enqueue) if exhausted
    spend = await spending.budget_exhausted(db, agent)
    if spend is not None:
        from sleeper_service.runtime import notify
        from sleeper_service.runtime.runner import mark_job

        await mark_job(
            job.id,
            "budget_exceeded",
            f"monthly spend {spend} reached limit {agent.spending_limit}",
        )
        await notify.notify(
            agent.id,
            "budget",
            f"Sleeper Service: budget exceeded — {agent.name}",
            f"Agent {agent.name} hit its monthly spending limit "
            f"({spend} / {agent.spending_limit}). Jobs are being refused.",
        )
        await db.refresh(job)
        return job, False

    if not sync:
        pool = await get_pool()
        await pool.enqueue_job("run_job", str(job.id))
    return job, False


@router.post("/agents/{agent_id}/jobs", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
async def submit_job(
    agent_id: uuid.UUID,
    body: JobSubmit,
    sync: bool = False,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> Job:
    agent = await _get_agent_for(db, principal, agent_id, submit=True)
    version = await _resolve_version(db, agent, body)
    tenant = await db.get(Tenant, agent.tenant_id)

    if isinstance(principal, UserPrincipal):
        auth_ctx = {
            "type": "user",
            "user_id": str(principal.user.id),
            "team_role": principal.roles.get(agent.team_id),
            "tenant_id": str(agent.tenant_id),
            "team_id": str(agent.team_id),
            "agent_id": str(agent.id),
        }
    else:
        auth_ctx = {
            "type": "invoke_key",
            "key_id": str(principal.key.id),
            "scope": principal.scope,
            "scope_id": str(principal.scope_id),
            "tenant_id": str(agent.tenant_id),
            "team_id": str(agent.team_id),
            "agent_id": str(agent.id),
        }

    if body.context.links:
        link_error = links.check_links(body.context.links, tenant.settings or {})
        if link_error is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, link_error)

    if body.callback_url:
        try:
            validate_callback_url(body.callback_url, tenant.settings or {})
        except OutboundUrlError as e:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e

    if body.context.files:
        # Files are tenant-scoped and invoke keys below the tenant have no
        # file surface (files.py _check_tenant_access). Referencing a file
        # here would be that read by another door: the runner inlines the
        # content into the prompt and the key collects it from the job
        # output — so the job surface enforces the same boundary.
        if isinstance(principal, InvokePrincipal) and principal.scope != KeyScope.TENANT:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Invoke keys scoped below the tenant cannot reference files",
            )
        for file_id in body.context.files:
            file = await db.get(File, file_id)
            if file is None or file.tenant_id != agent.tenant_id:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown file {file_id}")

    job, existed = await create_job(
        db,
        agent,
        version,
        context=body.context.model_dump(mode="json"),
        callback_url=body.callback_url,
        user_ctx=body.user_ctx,
        auth_ctx=auth_ctx,
        idempotency_key=body.idempotency_key,
        sync=sync,
    )
    if existed or job.status == "budget_exceeded":
        return job

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

    return job  # async path was already enqueued by create_job


async def _get_job_for(db: AsyncSession, principal: Principal, job_id: uuid.UUID) -> Job:
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
) -> JobOut:
    job = await _get_job_for(db, principal, job_id)
    return await _with_feedback_url(db, job)


async def _with_feedback_url(db: AsyncSession, job: Job) -> JobOut:
    from sleeper_service.runtime.learning import feedback_url
    from sleeper_service.runtime.memory import learning_enabled

    out = JobOut.model_validate(job)
    agent = await db.get(Agent, job.agent_id)
    if agent is not None and learning_enabled(agent.options or {}):
        out.feedback_url = feedback_url(job.id)
    return out


@router.get("/jobs/{job_id}/events", response_model=list[JobEventOut])
async def get_job_events(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> list[JobEvent]:
    await _get_job_for(db, principal, job_id)
    return list(
        await db.scalars(select(JobEvent).where(JobEvent.job_id == job_id).order_by(JobEvent.id))
    )


@router.get("/jobs/{job_id}/tree", response_model=JobTreeOut)
async def get_job_tree(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> JobTreeOut:
    """The full delegation tree rooted at this job (parent_job_id links)."""
    root = await _get_job_for(db, principal, job_id)

    visited: set[uuid.UUID] = set()

    async def build(node: Job, depth: int = 0) -> JobTreeOut:
        visited.add(node.id)
        out = JobTreeOut.model_validate(node)
        if depth >= 50:
            out.children = []
            return out
        children = await db.scalars(
            select(Job).where(Job.parent_job_id == node.id).order_by(Job.created_at)
        )
        visible_children = []
        for child in children:
            if child.id in visited:
                continue
            try:
                await _get_agent_for(db, principal, child.agent_id, submit=False)
            except HTTPException:
                continue
            visible_children.append(await build(child, depth + 1))
        out.children = visible_children
        return out

    return await build(root)


@router.get("/agents/{agent_id}/jobs", response_model=list[JobOut])
async def list_jobs(
    agent_id: uuid.UUID,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> list[Job]:
    """Browse an agent's jobs, newest first (viewer+ or in-scope invoke key)."""
    await _get_agent_for(db, principal, agent_id, submit=False)
    stmt = (
        select(Job)
        .where(Job.agent_id == agent_id)
        .order_by(Job.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if status_filter is not None:
        stmt = stmt.where(Job.status == status_filter)
    return list(await db.scalars(stmt))


@router.post("/jobs/{job_id}/retry", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
async def retry_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_principal),
) -> Job:
    """Re-queue a terminally failed job (dead_letter/failed/timeout) — e.g.
    after a provider outage ends. Same job row: full history stays attached."""
    job = await _get_job_for(db, principal, job_id)
    agent = await _get_agent_for(db, principal, job.agent_id, submit=True)
    if agent.archived_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Agent {agent.name!r} is archived and cannot take new work"
        )
    if job.status not in ("dead_letter", "failed", "timeout"):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Only failed jobs can be retried (status: {job.status})"
        )
    job.status = "queued"
    job.output = None
    job.error = None
    job.started_at = None
    job.finished_at = None
    db.add(JobEvent(job_id=job.id, type="retried", data={"by": "api"}))
    await db.commit()
    await db.refresh(job)
    pool = await get_pool()
    await pool.enqueue_job("run_job", str(job.id))
    return job
