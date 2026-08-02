"""arq worker: job execution with retries/DLQ and callback delivery."""

import uuid
from typing import ClassVar

from arq import Retry
from arq.connections import RedisSettings

from sleeper_service.config import get_settings
from sleeper_service.db.models import Job
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.observability import setup_tracing
from sleeper_service.runtime import callbacks
from sleeper_service.runtime.runner import TransientJobError, execute_job, mark_job


async def run_job(ctx: dict, job_id: str) -> None:
    settings = get_settings()
    try:
        await execute_job(uuid.UUID(job_id))
    except TransientJobError as e:
        if ctx["job_try"] >= settings.job_max_tries:
            await mark_job(
                uuid.UUID(job_id),
                "dead_letter",
                f"retries exhausted after {ctx['job_try']} tries: {e}",
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
        else:
            raise Retry(defer=15 * 2 ** (ctx["job_try"] - 1)) from e


async def startup(ctx: dict) -> None:
    setup_tracing()


class WorkerSettings:
    functions: ClassVar = [run_job, deliver_callback]
    on_startup = startup
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    max_tries = max(get_settings().job_max_tries, get_settings().callback_max_tries)
    job_timeout = 3700  # > max version timeout_s; the runner enforces the real cap
