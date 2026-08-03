"""Feedback-driven learning (BUILD_PLAN § Memory & learning).

Responses from learning-enabled agents carry a signed, single-job-scoped
feedback URL — only the party that received the result can vote. A background
job folds the vote into memory deterministically (no fine-tuning, no LLM
judge): a "+" reinforces what worked, a "-" with a comment becomes a corrective
rule. Cheap, reversible, auditable — every fold is a new memory version.
"""

import hashlib
import hmac
import uuid
from datetime import UTC, datetime

from sleeper_service.config import get_settings
from sleeper_service.db.models import Agent, Feedback, Job, Tenant
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import hooks, memory


def feedback_token(job_id: uuid.UUID) -> str:
    digest = hmac.new(
        get_settings().secret_key.encode(), f"feedback:{job_id}".encode(), hashlib.sha256
    )
    return digest.hexdigest()[:40]


def feedback_url(job_id: uuid.UUID) -> str:
    base = get_settings().public_base_url.rstrip("/")
    return f"{base}/v1/feedback/{job_id}?token={feedback_token(job_id)}"


def _summarize(job: Job) -> str:
    if job.output and isinstance(job.output.get("summary"), str):
        text = job.output["summary"]
    else:
        text = job.payload.get("prompt", "")
    return text[:200].replace("\n", " ")


async def fold_feedback(feedback_id: uuid.UUID) -> None:
    """Fold one vote into the agent's memory (arq: fold_feedback)."""
    async with get_sessionmaker()() as db:
        fb = await db.get(Feedback, feedback_id)
        if fb is None:
            return
        job = await db.get(Job, fb.job_id)
        agent = await db.get(Agent, job.agent_id)
        if not memory.learning_enabled(agent.options or {}):
            return
        current = await memory.latest_memory(db, agent.id)
        tenant = await db.get(Tenant, agent.tenant_id)

        # Poisoning defense: a hostile comment must not become a memory rule.
        comment = (fb.comment or "").strip()
        if comment and await hooks.screen_untrusted(db, [comment], tenant, agent) is not None:
            comment = ""

    date = datetime.now(UTC).date().isoformat()
    if fb.vote > 0:
        lesson = f"- ✔ {date}: positive feedback on: {_summarize(job)}"
    elif comment:
        lesson = f"- ✘ {date}: correction from feedback: {comment[:300]}"
    else:
        lesson = f"- ✘ {date}: negative feedback on: {_summarize(job)}"

    content = current.content if current else ""
    if memory.LESSONS_HEADER not in content:
        content = (content + f"\n\n{memory.LESSONS_HEADER}\n").lstrip()
    content = content.rstrip() + "\n" + lesson + "\n"

    # The lesson line is derived from screened parts; skip the whole-document
    # screen so one historic false positive can't freeze learning forever.
    await memory.write_memory(
        agent.id,
        content,
        job.id,
        screen=False,
        pending=memory.approval_required(agent.options or {}),
    )
