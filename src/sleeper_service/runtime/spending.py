"""Spending limit checks (BUILD_PLAN § Spending limits).

Limits are monthly (UTC calendar month) per agent. Enforcement is pre-flight
at submission and re-checked in the runner before the model call; cost
accrues on job rows and rolls up by summation.
"""

import uuid
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.db.models import Agent, Job


def month_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def month_spend(db: AsyncSession, agent_id: uuid.UUID) -> Decimal:
    total = await db.scalar(
        select(func.coalesce(func.sum(Job.cost), 0)).where(
            Job.agent_id == agent_id, Job.created_at >= month_start()
        )
    )
    return Decimal(total)


async def budget_exhausted(db: AsyncSession, agent: Agent) -> Decimal | None:
    """Return the current month's spend if the agent's limit is exhausted."""
    if agent.spending_limit is None:
        return None
    spend = await month_spend(db, agent.id)
    return spend if spend >= agent.spending_limit else None
