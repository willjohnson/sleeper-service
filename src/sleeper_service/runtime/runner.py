"""Job execution: the PydanticAI loop with runtime guardrails.

Statuses written here are terminal (succeeded / failed / iteration_limit /
timeout) except for transient provider failures, which raise
TransientJobError so the caller decides: the arq worker retries with backoff
(dead_letter after max tries), the sync API path fails the job immediately.
"""

import asyncio
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import httpx
from pydantic_ai import Agent as PaiAgent
from pydantic_ai import BinaryContent, StructuredDict
from pydantic_ai.exceptions import ModelHTTPError, UsageLimitExceeded
from pydantic_ai.usage import RunUsage, UsageLimits

from sleeper_service import storage
from sleeper_service.config import get_settings
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    File,
    Job,
    JobEvent,
    Model,
    Tenant,
)
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime.providers import build_model, resolve_api_key

TEXT_TYPES = ("text/", "application/json", "application/xml", "application/csv")


class TransientJobError(Exception):
    """Provider hiccup (429/5xx/network): worth retrying."""


def _now() -> datetime:
    return datetime.now(UTC)


def _calc_cost(usage: RunUsage, model_name: str) -> Decimal:
    try:
        from genai_prices import calc_price

        return Decimal(str(calc_price(usage, model_ref=model_name).total_price))
    except Exception:
        return Decimal(0)


async def _build_user_content(payload: dict) -> list:
    content: list = [payload["prompt"]]
    for file_id in payload.get("files", []):
        async with get_sessionmaker()() as db:
            file = await db.get(File, uuid.UUID(file_id))
        if file is None:
            continue
        data = await storage.get_object(file.object_key)
        if file.content_type.startswith(TEXT_TYPES):
            name = file.object_key.rsplit("/", 1)[-1]
            content.append(f"\n--- file: {name} ---\n{data.decode(errors='replace')}")
        else:
            content.append(BinaryContent(data=data, media_type=file.content_type))
    return content


async def execute_job(job_id: uuid.UUID, *, sync_cap: bool = False) -> None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db:
        job = await db.get(Job, job_id)
        if job is None or job.status not in ("queued", "running"):
            return
        agent = await db.get(Agent, job.agent_id)
        version = await db.get(AgentVersion, job.agent_version_id)
        tenant = await db.get(Tenant, agent.tenant_id)
        model_row = await db.get(Model, version.model_id)

        job.status = "running"
        job.started_at = _now()
        db.add(JobEvent(job_id=job.id, type="started", data={}))
        await db.commit()

        api_key = await resolve_api_key(db, agent.tenant_id, model_row.provider)

    model = build_model(model_row.model_string, api_key)
    instructions = "\n\n".join(
        p for p in (tenant.system_prompt.strip(), version.prompt.strip()) if p
    )
    output_type = (
        StructuredDict(version.output_schema) if version.output_schema else str
    )
    pai_agent = PaiAgent(
        model,
        instructions=instructions,
        output_type=output_type,
        model_settings=version.params or None,
    )
    limits = UsageLimits(request_limit=version.max_iterations)
    timeout_s = version.timeout_s
    if sync_cap:
        timeout_s = min(timeout_s, get_settings().sync_job_timeout_s)

    user_content = await _build_user_content(job.payload)

    status = "succeeded"
    output: dict | None = None
    error: str | None = None
    usage: RunUsage | None = None
    try:
        async with asyncio.timeout(timeout_s):
            result = await pai_agent.run(user_content, usage_limits=limits)
        raw = result.output
        output = raw if isinstance(raw, dict) else {"text": raw}
        usage = result.usage()
    except TimeoutError:
        status, error = "timeout", f"Job exceeded wall-clock timeout of {timeout_s}s"
    except UsageLimitExceeded as e:
        status, error = "iteration_limit", str(e)
    except ModelHTTPError as e:
        if e.status_code == 429 or e.status_code >= 500:
            await _record_transient(job_id, str(e))
            raise TransientJobError(str(e)) from e
        status, error = "failed", str(e)
    except httpx.TransportError as e:
        await _record_transient(job_id, str(e))
        raise TransientJobError(str(e)) from e
    except Exception as e:
        status, error = "failed", f"{type(e).__name__}: {e}"

    async with sessionmaker() as db:
        job = await db.get(Job, job_id)
        job.status = status
        job.output = output
        job.error = error
        job.finished_at = _now()
        if usage is not None:
            job.tokens_in = usage.input_tokens or 0
            job.tokens_out = usage.output_tokens or 0
            job.cost = _calc_cost(usage, model_row.name)
        db.add(
            JobEvent(
                job_id=job.id,
                type="finished",
                data={"status": status, **({"error": error} if error else {})},
            )
        )
        await db.commit()


async def _record_transient(job_id: uuid.UUID, message: str) -> None:
    async with get_sessionmaker()() as db:
        db.add(JobEvent(job_id=job_id, type="transient_error", data={"error": message}))
        await db.commit()


async def mark_job(job_id: uuid.UUID, status: str, error: str | None = None) -> None:
    """Terminal bookkeeping from outside the runner (retry exhaustion, etc.)."""
    async with get_sessionmaker()() as db:
        job = await db.get(Job, job_id)
        if job is None:
            return
        job.status = status
        job.error = error
        job.finished_at = _now()
        db.add(JobEvent(job_id=job.id, type="finished", data={"status": status}))
        await db.commit()
