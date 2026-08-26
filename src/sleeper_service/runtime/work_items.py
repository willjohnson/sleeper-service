"""Shared human-work inbox and agent-to-human escalation.

Work items are projections over domain records, not replacements for them:
memory approval still changes ``MemoryVersion.status`` and an escalation still
belongs to the job that raised it. This module keeps those records and their
inbox lifecycle synchronized.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic_ai.toolsets import AbstractToolset, FunctionToolset
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.db.models import Agent, JobEvent, MemoryVersion, WorkItem
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import notify

logger = logging.getLogger(__name__)


class WorkItemConflict(ValueError):
    pass


def escalation_enabled(agent_options: dict) -> bool:
    return agent_options.get("human_escalation") is True


def add_memory_approval_item(db: AsyncSession, agent: Agent, version: MemoryVersion) -> WorkItem:
    item = WorkItem(
        tenant_id=agent.tenant_id,
        team_id=agent.team_id,
        agent_id=agent.id,
        job_id=version.source_job_id,
        memory_version_id=version.id,
        kind="memory_approval",
        title=f"Review memory v{version.version_no} for {agent.name}",
        details={"memory_version_no": version.version_no},
    )
    db.add(item)
    return item


async def ensure_memory_approval_item(
    db: AsyncSession, agent: Agent, version: MemoryVersion
) -> WorkItem:
    item = await db.scalar(
        select(WorkItem).where(WorkItem.memory_version_id == version.id).with_for_update()
    )
    if item is None:
        item = add_memory_approval_item(db, agent, version)
        await db.flush()
    return item


async def notify_created(item: WorkItem, agent_name: str) -> None:
    if item.kind == "memory_approval":
        body = f"{item.title}. Open the human-work inbox to approve or reject it."
    else:
        reason = str((item.details or {}).get("reason", "Human review requested."))
        body = f"Agent {agent_name} escalated job {item.job_id}: {reason}"
    try:
        await notify.notify(
            item.agent_id,
            "human_attention",
            f"Sleeper Service: {item.title}",
            body,
            dedup_key=f"work-item:{item.id}",
        )
    except Exception:
        # The durable inbox item is the source of truth. A Redis or delivery
        # outage must not undo the escalation or strand the parent job.
        logger.exception("work-item notification failed for %s", item.id)


async def resolve_work_item(
    db: AsyncSession,
    item: WorkItem,
    *,
    resolution: str,
    response: str | None,
    resolved_by_user_id: uuid.UUID,
) -> WorkItem:
    if item.status != "open":
        raise WorkItemConflict(f"Work item is already {item.status}")

    if item.kind == "memory_approval":
        if resolution not in ("approved", "rejected"):
            raise WorkItemConflict("Memory approvals must be approved or rejected")
        version = await db.get(MemoryVersion, item.memory_version_id)
        if version is None:
            raise WorkItemConflict("The memory version no longer exists")
        if version.status != "pending":
            raise WorkItemConflict(f"Memory version is already {version.status}")
        version.status = "active" if resolution == "approved" else "rejected"
        item.status = "resolved"
    elif item.kind == "human_escalation":
        if resolution not in ("resolved", "dismissed"):
            raise WorkItemConflict("Escalations must be resolved or dismissed")
        item.status = resolution
    else:  # protected by the DB CHECK, defensive for partially migrated rows
        raise WorkItemConflict(f"Unsupported work-item kind {item.kind!r}")

    item.resolution = resolution
    item.response = {"text": response.strip()} if response and response.strip() else None
    item.resolved_by_user_id = resolved_by_user_id
    item.resolved_at = datetime.now(UTC)
    if item.job_id is not None:
        db.add(
            JobEvent(
                job_id=item.job_id,
                type="human_work_resolved",
                data={
                    "work_item_id": str(item.id),
                    "kind": item.kind,
                    "resolution": resolution,
                },
            )
        )
    await db.flush()
    return item


def build_escalation_toolset(
    agent: Agent, job_id: uuid.UUID, created_ids: list[uuid.UUID]
) -> AbstractToolset | None:
    """Expose escalation only when the agent opted into the capability."""
    if not escalation_enabled(agent.options or {}):
        return None

    async def escalate_to_human(
        summary: str,
        reason: str,
        severity: Literal["low", "medium", "high"] = "medium",
        requested_action: str = "Review and decide how the workflow should continue.",
    ) -> str:
        """Escalate this job to the owning team when human judgment is needed.

        Provide a short summary, why automation should stop, severity, and the
        concrete decision or action requested from the person reviewing it.
        """
        async with get_sessionmaker()() as db:
            item = WorkItem(
                tenant_id=agent.tenant_id,
                team_id=agent.team_id,
                agent_id=agent.id,
                job_id=job_id,
                kind="human_escalation",
                title=summary.strip()[:500] or f"Human review requested by {agent.name}",
                details={
                    "reason": reason.strip()[:10_000],
                    "severity": severity,
                    "requested_action": requested_action.strip()[:10_000],
                },
            )
            db.add(item)
            db.add(
                JobEvent(
                    job_id=job_id,
                    type="human_escalated",
                    data={
                        "work_item_id": str(item.id),
                        "severity": severity,
                        "summary": item.title,
                    },
                )
            )
            await db.commit()
            await db.refresh(item)
        created_ids.append(item.id)
        await notify_created(item, agent.name)
        return (
            f"Escalation {item.id} was recorded and the owning team was notified. "
            "Stop autonomous work and return a concise summary for the workflow."
        )

    return FunctionToolset([escalate_to_human], id="human-escalation")
