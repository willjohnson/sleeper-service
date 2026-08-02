"""Scheduled cleanup (BUILD_PLAN § Files, § Security: log retention).

Runs hourly from the worker's cron. Two per-tenant policies, both opt-in via
tenant settings:

- ``file_ttl_days``: payload files get expires_at at upload; expired objects
  are removed from MinIO and their rows deleted.
- ``job_retention_days``: jobs older than this keep their row, statuses,
  token counts, and cost (audit + spend rollups stay intact) but have their
  raw payload/output content pruned.
"""

import logging
from datetime import UTC, datetime, timedelta

import anyio
from sqlalchemy import select, update

from sleeper_service.db.models import Agent, File, Job, Tenant
from sleeper_service.db.session import get_sessionmaker

logger = logging.getLogger(__name__)

PRUNED_MARKER = {"pruned": True}


def file_expiry(tenant_settings: dict) -> datetime | None:
    days = tenant_settings.get("file_ttl_days")
    if not isinstance(days, int | float) or days <= 0:
        return None
    return datetime.now(UTC) + timedelta(days=days)


async def cleanup_tick() -> dict:
    """One pass of both policies. Returns counts (also logged)."""
    now = datetime.now(UTC)
    files_deleted = 0
    jobs_pruned = 0
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as db:
        expired = list(
            await db.scalars(
                select(File).where(File.expires_at.is_not(None), File.expires_at < now)
            )
        )
        for file in expired:

            def _rm(key: str = file.object_key) -> None:
                from sleeper_service.config import get_settings
                from sleeper_service.storage import _fs

                path = f"{get_settings().minio_bucket}/{key}"
                if _fs().exists(path):
                    _fs().rm_file(path)

            try:
                await anyio.to_thread.run_sync(_rm)
            except Exception:
                logger.exception("failed to delete expired object %s", file.object_key)
                continue
            await db.delete(file)
            files_deleted += 1
        await db.commit()

        tenants = list(await db.scalars(select(Tenant)))
        for tenant in tenants:
            days = (tenant.settings or {}).get("job_retention_days")
            if not isinstance(days, int | float) or days <= 0:
                continue
            cutoff = now - timedelta(days=days)
            agent_ids = select(Agent.id).where(Agent.tenant_id == tenant.id)
            result = await db.execute(
                update(Job)
                .where(
                    Job.agent_id.in_(agent_ids),
                    Job.created_at < cutoff,
                    Job.payload != PRUNED_MARKER,
                )
                .values(payload=PRUNED_MARKER, output=None)
            )
            jobs_pruned += result.rowcount or 0
        await db.commit()

    if files_deleted or jobs_pruned:
        logger.info("retention: deleted %d files, pruned %d jobs", files_deleted, jobs_pruned)
    return {"files_deleted": files_deleted, "jobs_pruned": jobs_pruned}
