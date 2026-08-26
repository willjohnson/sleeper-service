"""Job execution: pre-hooks → PydanticAI loop → post-hooks, with guardrails.

Statuses written here are terminal (succeeded / escalated / failed / rejected /
budget_exceeded / iteration_limit / timeout) except for transient provider
failures, which raise TransientJobError so the caller decides: the arq worker
retries with backoff (dead_letter after max tries), the sync API path fails
the job immediately.
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
from sleeper_service.constants import TEXT_CONTENT_TYPES
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    File,
    Job,
    JobEvent,
    MemoryVersion,
    Model,
    Tenant,
)
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import hooks, links, memory, notify, spending
from sleeper_service.runtime.delegation import build_delegation_toolset
from sleeper_service.runtime.providers import build_model, resolve_api_key
from sleeper_service.runtime.toolsets import (
    GrantError,
    build_mcp_toolsets,
    build_store_toolset,
)
from sleeper_service.runtime.work_items import build_escalation_toolset


class TransientJobError(Exception):
    """Provider hiccup (429/5xx/network): worth retrying."""


class _BudgetExceededMidRun(Exception):
    """Accrued cost crossed the remaining monthly budget between model calls."""


def _now() -> datetime:
    return datetime.now(UTC)


def _calc_cost(usage: RunUsage, model_name: str) -> Decimal:
    try:
        from genai_prices import calc_price

        return Decimal(str(calc_price(usage, model_ref=model_name).total_price))
    except Exception:
        return Decimal(0)


async def _load_file_content(payload: dict, tenant_id: uuid.UUID) -> tuple[list, list[str]]:
    """Returns (model content parts, untrusted text for injection screening).

    Every ingress validates file tenancy before the job is created; the check
    is repeated here so a payload that reaches the runner by some other route
    still cannot pull another tenant's file into the prompt.
    """
    parts: list = []
    texts: list[str] = []
    for file_id in payload.get("files", []):
        async with get_sessionmaker()() as db:
            file = await db.get(File, uuid.UUID(file_id))
        if file is None or file.tenant_id != tenant_id:
            continue
        data = await storage.get_object(file.object_key)
        if file.content_type.startswith(TEXT_CONTENT_TYPES):
            name = file.object_key.rsplit("/", 1)[-1]
            block = f"\n--- file: {name} ---\n{data.decode(errors='replace')}"
            parts.append(block)
            texts.append(block)
        else:
            parts.append(BinaryContent(data=data, media_type=file.content_type))
    return parts, texts


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

        # Budget pre-flight (re-checked here so queued backlogs can't overrun).
        # What's left of the month's budget also bounds this single run: the
        # loop below re-checks accrued cost between model calls.
        remaining_budget: Decimal | None = None
        if agent.spending_limit is not None:
            spend = await spending.month_spend(db, agent.id)
            if spend >= agent.spending_limit:
                await _finalize(
                    job_id,
                    "budget_exceeded",
                    error=f"monthly spend {spend} reached limit {agent.spending_limit}",
                )
                await notify.notify(
                    agent.id,
                    "budget",
                    f"Sleeper Service: budget exceeded — {agent.name}",
                    f"Agent {agent.name} hit its monthly spending limit "
                    f"({spend} / {agent.spending_limit}). Jobs are being refused.",
                )
                return
            remaining_budget = agent.spending_limit - spend

        # Memory: inject the latest active version and pin it on the job.
        # A pre-pinned memory_version_id (eval-gate runs) wins — that's how a
        # pending memory gets evaluated before approval.
        memory_text: str | None = None
        agent_options = agent.options or {}
        if memory.memory_enabled(agent_options):
            if job.memory_version_id is not None:
                pinned = await db.get(MemoryVersion, job.memory_version_id)
                if pinned is not None:
                    memory_text = pinned.content
            else:
                mem_version = await memory.latest_memory(db, agent.id)
                if mem_version is not None:
                    job.memory_version_id = mem_version.id
                    memory_text = mem_version.content

        job.status = "running"
        job.started_at = _now()
        db.add(JobEvent(job_id=job.id, type="started", data={}))
        await db.commit()

        api_key = await resolve_api_key(db, agent, model_row.provider)
        try:
            toolsets = await build_mcp_toolsets(
                db,
                agent.tenant_id,
                version.tool_grants or [],
                job.user_ctx,
                job.auth_ctx,
            )
            store_toolset = await build_store_toolset(
                db, agent.tenant_id, version.data_store_grants or []
            )
            if store_toolset is not None:
                toolsets.append(store_toolset)
        except GrantError as e:
            await _finalize(job_id, "failed", error=str(e))
            return

    delegation_toolset = build_delegation_toolset(agent, job_id)
    if delegation_toolset is not None:
        toolsets.append(delegation_toolset)

    escalation_ids: list[uuid.UUID] = []
    escalation_toolset = build_escalation_toolset(agent, job_id, escalation_ids)
    if escalation_toolset is not None:
        toolsets.append(escalation_toolset)

    memory_proposals: list[str] = []
    if memory.memory_enabled(agent_options):

        async def update_memory(new_content: str) -> str:
            """Replace your memory document (your accumulated notes). The new
            content is validated and saved after this job completes."""
            memory_proposals.append(new_content)
            return "memory update queued for validation after this job"

        from pydantic_ai.toolsets import FunctionToolset

        toolsets.append(FunctionToolset([update_memory], id="memory"))

    # Assemble user content; collect untrusted text for the injection screen
    prompt_text = job.payload["prompt"]
    file_parts, file_texts = await _load_file_content(job.payload, tenant.id)
    link_blocks = await links.fetch_links(job.payload.get("links", []), tenant.settings or {})
    user_content: list = [prompt_text, *file_parts, *link_blocks]
    untrusted = [prompt_text, *file_texts, *link_blocks]

    # Pre-hook: injection screen (default on; heuristics + optional
    # cheap-model classifier tier)
    if hooks.injection_screen_enabled(tenant.settings or {}, agent.options or {}):
        async with sessionmaker() as db:
            matched = await hooks.screen_untrusted(db, untrusted, tenant, agent)
        if matched is not None:
            async with sessionmaker() as db:
                db.add(
                    JobEvent(
                        job_id=job_id,
                        type="injection_detected",
                        data={"rule": matched},
                    )
                )
                await db.commit()
            await _finalize(
                job_id, "rejected", error=f"prompt-injection screen matched rule: {matched}"
            )
            return

    model = build_model(model_row.model_string, api_key)
    instructions = "\n\n".join(
        p
        for p in (
            tenant.system_prompt.strip(),
            version.prompt.strip(),
            memory.render_memory_section(memory_text) if memory_text else "",
        )
        if p
    )
    output_type = StructuredDict(version.output_schema) if version.output_schema else str
    pai_agent = PaiAgent(
        model,
        instructions=instructions,
        output_type=output_type,
        model_settings=version.params or None,
        toolsets=toolsets or None,
        # Retries stay above the request cap so max_iterations is the binding
        # guardrail (UsageLimitExceeded → iteration_limit, a first-class status).
        retries=version.max_iterations,
    )
    limits = UsageLimits(request_limit=version.max_iterations)
    timeout_s = version.timeout_s
    if sync_cap:
        timeout_s = min(timeout_s, get_settings().sync_job_timeout_s)

    status = "succeeded"
    output: dict | None = None
    error: str | None = None
    usage: RunUsage | None = None
    events: list[tuple[str, dict]] = []
    try:
        async with asyncio.timeout(timeout_s):
            # iter() instead of run(): between model calls, check the cost
            # accrued so far against what's left of the monthly budget, so a
            # runaway job is bounded by $ and not only by iterations/timeout.
            async with pai_agent.iter(user_content, usage_limits=limits) as agent_run:
                async for _node in agent_run:
                    if remaining_budget is None:
                        continue
                    run_cost = _calc_cost(agent_run.usage, model_row.name)
                    if run_cost >= remaining_budget:
                        usage = agent_run.usage
                        raise _BudgetExceededMidRun(
                            f"mid-run cost {run_cost} reached the remaining monthly "
                            f"budget {remaining_budget}"
                        )
                result = agent_run.result
        raw = result.output
        output = raw if isinstance(raw, dict) else {"text": raw}
        usage = result.usage
    except _BudgetExceededMidRun as e:
        status, error = "budget_exceeded", str(e)
    except TimeoutError:
        status, error = "timeout", f"Job exceeded wall-clock timeout of {timeout_s}s"
    except asyncio.CancelledError:
        # Cancelled from outside (a delegating parent timed out, or the worker
        # is shutting down). CancelledError is BaseException, so without this
        # clause the job would be stranded in `running` forever. Finalize,
        # then re-raise so the canceller's own control flow proceeds.
        await _finalize(
            job_id, "failed", error="cancelled: parent job timed out or worker shut down"
        )
        raise
    except UsageLimitExceeded as e:
        status, error = "iteration_limit", str(e)
    except ModelHTTPError as e:
        if e.status_code == 429 or e.status_code >= 500:
            await _record_event(job_id, "transient_error", {"error": str(e)})
            raise TransientJobError(str(e)) from e
        status, error = "failed", str(e)
    except httpx.TransportError as e:
        await _record_event(job_id, "transient_error", {"error": str(e)})
        raise TransientJobError(str(e)) from e
    except Exception as e:
        status, error = "failed", f"{type(e).__name__}: {e}"

    # Post-hooks
    if status == "succeeded" and version.output_schema:
        schema_error = hooks.validate_output_schema(output, version.output_schema)
        if schema_error is not None:
            status, error, output = "failed", schema_error, None
    if status == "succeeded" and hooks.pii_redaction_enabled(agent.options or {}):
        output, redactions = hooks.redact_pii(output)
        if redactions:
            events.append(("pii_redacted", {"count": redactions}))
    if status == "succeeded" and escalation_ids:
        # Escalation is an intentional, terminal handoff rather than a
        # failure. Preserve any schema-valid agent result as supporting
        # context and put stable work-item ids in the callback/result.
        status = "escalated"
        output = {
            "work_item_ids": [str(item_id) for item_id in escalation_ids],
            "result": output,
        }
    if status == "succeeded" and memory_proposals:
        # Post-hook memory write: screened (poisoning defense), size-capped,
        # and pending owner approval when governance requires it
        await memory.write_memory(
            agent.id,
            memory_proposals[-1],
            job_id,
            pending=memory.approval_required(agent_options),
        )

    await _finalize(
        job_id,
        status,
        output=output,
        error=error,
        usage=usage,
        model_name=model_row.name,
        extra_events=events,
    )
    if status == "budget_exceeded":
        await notify.notify(
            agent.id,
            "budget",
            f"Sleeper Service: budget exceeded — {agent.name}",
            f"Agent {agent.name} crossed its monthly spending limit mid-run "
            f"({agent.spending_limit}); the job was stopped.",
        )


async def _finalize(
    job_id: uuid.UUID,
    status: str,
    *,
    output: dict | None = None,
    error: str | None = None,
    usage: RunUsage | None = None,
    model_name: str | None = None,
    extra_events: list[tuple[str, dict]] | None = None,
) -> None:
    async with get_sessionmaker()() as db:
        job = await db.get(Job, job_id)
        if job is None:
            return
        job.status = status
        job.output = output
        job.error = error
        job.finished_at = _now()
        if usage is not None and model_name is not None:
            job.tokens_in = usage.input_tokens or 0
            job.tokens_out = usage.output_tokens or 0
            job.cost = _calc_cost(usage, model_name)
        for event_type, data in extra_events or []:
            db.add(JobEvent(job_id=job.id, type=event_type, data=data))
        db.add(
            JobEvent(
                job_id=job.id,
                type="finished",
                data={"status": status, **({"error": error} if error else {})},
            )
        )
        is_eval = job.is_eval
        agent_id = job.agent_id
        await db.commit()

    if not is_eval and status in ("failed", "dead_letter", "timeout", "iteration_limit"):
        await notify.check_error_rate(agent_id)


async def _record_event(job_id: uuid.UUID, event_type: str, data: dict) -> None:
    async with get_sessionmaker()() as db:
        db.add(JobEvent(job_id=job_id, type=event_type, data=data))
        await db.commit()


async def mark_job(job_id: uuid.UUID, status: str, error: str | None = None) -> None:
    """Terminal bookkeeping from outside the runner (retry exhaustion, etc.)."""
    await _finalize(job_id, status, error=error)
