"""Team alerting via Apprise (BUILD_PLAN § Notifications & alerting).

Channels subscribe to event types (dead_letter | budget | error_rate).
Alerts dedupe per agent+event in a 15-minute window so a broken agent
doesn't page 500 times.
"""

import logging
import uuid

import anyio
import apprise

from sleeper_service.crypto import decrypt
from sleeper_service.db.models import Agent, NotifChannel
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.redis_client import get_redis

logger = logging.getLogger(__name__)

DEDUP_WINDOW_S = 900


async def notify(agent_id: uuid.UUID, event_type: str, title: str, body: str) -> None:
    """Alert the owning team's channels subscribed to event_type."""
    redis = get_redis()
    dedup_key = f"alert:{agent_id}:{event_type}"
    if not await redis.set(dedup_key, 1, nx=True, ex=DEDUP_WINDOW_S):
        return  # already alerted inside the window

    from sqlalchemy import select

    async with get_sessionmaker()() as db:
        agent = await db.get(Agent, agent_id)
        if agent is None:
            return
        channels = list(
            await db.scalars(select(NotifChannel).where(NotifChannel.team_id == agent.team_id))
        )
    urls = [decrypt(c.apprise_url_enc) for c in channels if event_type in (c.events or [])]
    if not urls:
        return

    def _send() -> None:
        ap = apprise.Apprise()
        for url in urls:
            ap.add(url)
        ap.notify(title=title, body=body)

    try:
        await anyio.to_thread.run_sync(_send)
    except Exception:
        logger.exception("alert delivery failed for agent %s (%s)", agent_id, event_type)


ERROR_RATE_WINDOW = 20
ERROR_RATE_MIN_SAMPLE = 10
ERROR_RATE_THRESHOLD = 0.5
COUNTED_STATUSES = ("succeeded", "failed", "dead_letter", "timeout", "iteration_limit")


async def check_error_rate(agent_id: uuid.UUID) -> None:
    """Alert when >=50% of the agent's last 20 real runs failed (min 10).
    Rejected/budget refusals are excluded — they are policy, not malfunction.
    The per-agent dedup window keeps this from paging repeatedly."""
    from sqlalchemy import select

    from sleeper_service.db.models import Job

    async with get_sessionmaker()() as db:
        recent = list(
            await db.scalars(
                select(Job.status)
                .where(
                    Job.agent_id == agent_id,
                    Job.is_eval.is_(False),
                    Job.status.in_(COUNTED_STATUSES),
                )
                .order_by(Job.created_at.desc())
                .limit(ERROR_RATE_WINDOW)
            )
        )
    if len(recent) < ERROR_RATE_MIN_SAMPLE:
        return
    failures = sum(1 for s in recent if s != "succeeded")
    rate = failures / len(recent)
    if rate >= ERROR_RATE_THRESHOLD:
        await notify(
            agent_id,
            "error_rate",
            "Sleeper Service: elevated error rate",
            f"{failures} of the last {len(recent)} jobs failed ({rate:.0%}).",
        )
