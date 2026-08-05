"""arq worker: job execution with retries/DLQ and callback delivery."""

import uuid
from typing import ClassVar

from arq import Retry
from arq.connections import RedisSettings
from arq.cron import cron

from sleeper_service.config import get_settings
from sleeper_service.db.models import Job
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.observability import setup_tracing
from sleeper_service.queue import job_deserializer, job_serializer
from sleeper_service.runtime import callbacks, notify
from sleeper_service.runtime.runner import TransientJobError, execute_job, mark_job


async def run_job(ctx: dict, job_id: str) -> None:
    settings = get_settings()
    if await _tenant_at_capacity(job_id):
        # Defer without burning a retry: concurrency pressure is not an error
        await ctx["redis"].enqueue_job("run_job", job_id, _defer_by=10)
        return
    try:
        await execute_job(uuid.UUID(job_id))
    except TransientJobError as e:
        if ctx["job_try"] >= settings.job_max_tries:
            await mark_job(
                uuid.UUID(job_id),
                "dead_letter",
                f"retries exhausted after {ctx['job_try']} tries: {e}",
            )
            async with get_sessionmaker()() as db:
                job = await db.get(Job, uuid.UUID(job_id))
            if job is not None:
                await notify.notify(
                    job.agent_id,
                    "dead_letter",
                    "Sleeper Service: job dead-lettered",
                    f"Job {job_id} exhausted {ctx['job_try']} tries and was "
                    f"dead-lettered. Last error: {e}",
                )
        else:
            # 10s, 20s, 40s, ...
            raise Retry(defer=10 * 2 ** (ctx["job_try"] - 1)) from e
        return

    async with get_sessionmaker()() as db:
        job = await db.get(Job, uuid.UUID(job_id))
    if job is not None and job.callback_url:
        await ctx["redis"].enqueue_job("deliver_callback", job_id)


async def deliver_callback(ctx: dict, job_id: str) -> None:
    settings = get_settings()
    try:
        await callbacks.deliver(uuid.UUID(job_id))
    except callbacks.CallbackDeliveryError as e:
        if ctx["job_try"] >= settings.callback_max_tries:
            await callbacks.record_callback_failure(
                uuid.UUID(job_id), f"gave up after {ctx['job_try']} tries: {e}"
            )
            async with get_sessionmaker()() as db:
                job = await db.get(Job, uuid.UUID(job_id))
            if job is not None:
                await notify.notify(
                    job.agent_id,
                    "callback_failed",
                    "Sleeper Service: callback delivery failed",
                    f"Callback for job {job_id} gave up after {ctx['job_try']} tries: {e}",
                )
        else:
            raise Retry(defer=15 * 2 ** (ctx["job_try"] - 1)) from e


async def fold_feedback(ctx: dict, feedback_id: str) -> None:
    from sleeper_service.runtime.learning import fold_feedback as fold

    await fold(uuid.UUID(feedback_id))


async def run_eval(ctx: dict, eval_run_id: str) -> None:
    from sleeper_service.runtime.evals import run_eval as run

    await run(uuid.UUID(eval_run_id))


async def _tenant_at_capacity(job_id: str) -> bool:
    from sqlalchemy import func, select

    from sleeper_service.db.models import Agent, Tenant

    async with get_sessionmaker()() as db:
        job = await db.get(Job, uuid.UUID(job_id))
        if job is None or job.is_eval:
            return False
        agent = await db.get(Agent, job.agent_id)
        if agent is None:
            return False
        tenant = await db.get(Tenant, agent.tenant_id)
        if tenant is None:
            return False
        cap = (tenant.settings or {}).get("max_concurrent_jobs")
        if not isinstance(cap, int) or cap <= 0:
            return False
        running = await db.scalar(
            select(func.count())
            .select_from(Job)
            .join(Agent, Job.agent_id == Agent.id)
            .where(
                Agent.tenant_id == tenant.id,
                Job.status == "running",
                Job.is_eval.is_(False),
            )
        )
        return running >= cap


async def cleanup(ctx: dict) -> dict:
    from sleeper_service.runtime.retention import cleanup_tick

    return await cleanup_tick()


async def startup(ctx: dict) -> None:
    setup_tracing()


class WorkerSettings:
    functions: ClassVar = [run_job, deliver_callback, fold_feedback, run_eval]
    cron_jobs: ClassVar = [cron(cleanup, minute=13)]  # hourly retention pass
    on_startup = startup
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    # JSON, not arq's default pickle — must match queue.get_pool(). See queue.py.
    job_serializer = staticmethod(job_serializer)
    job_deserializer = staticmethod(job_deserializer)
    max_tries = max(get_settings().job_max_tries, get_settings().callback_max_tries)
    job_timeout = 3700  # > max version timeout_s; the runner enforces the real cap
