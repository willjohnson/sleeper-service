"""Job execution: pre-hooks → PydanticAI loop → post-hooks, with guardrails.

Statuses written here are terminal (succeeded / escalated / failed / rejected /
budget_exceeded / iteration_limit / timeout) except for transient provider
failures, which raise TransientJobError so the caller decides: the arq worker
retries with backoff (dead_letter after max tries), the sync API path fails
the job immediately.
"""

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import httpx
from pydantic_ai import Agent as PaiAgent
from pydantic_ai import BinaryContent, PromptedOutput, StructuredDict
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
from sleeper_service.runtime.providers import (
    build_model,
    fetch_openrouter_cost,
    resolve_api_key,
)
from sleeper_service.runtime.toolsets import (
    GrantError,
    build_mcp_toolsets,
    build_store_toolset,
)
from sleeper_service.runtime.work_items import build_escalation_toolset

logger = logging.getLogger(__name__)


class TransientJobError(Exception):
    """Provider hiccup (429/5xx/network): worth retrying."""


class _BudgetExceededMidRun(Exception):
    """Accrued cost crossed the remaining monthly budget between model calls."""


def _now() -> datetime:
    return datetime.now(UTC)


# A tool call's arguments and result are model-controlled and unbounded — a
# write_file can carry a whole document — so the trail records their shape, not
# their content. Enough to answer "did it read the source, and did that work".
TOOL_EVENT_ARG_CHARS = 300

try:  # pragma: no cover - exercised only when pydantic-ai moves the constant
    from pydantic_ai._output import DEFAULT_OUTPUT_TOOL_NAME as _OUTPUT_TOOL_NAME
except ImportError:
    _OUTPUT_TOOL_NAME = "final_result"


def _tool_call_events(messages: list) -> list[tuple[str, dict]]:
    """One `tool_call` event per call the model made, in order.

    The job trail records lifecycle only, so a finished job cannot answer
    whether the model used its tools at all — and an agent that never called
    `read_file` still returns confident, plausible output. Only a tool *error*
    surfaced anywhere, and only because the exception text reached the job's
    error field.

    Outcomes are paired back onto their call by tool_call_id: a ToolReturnPart
    means it succeeded, a RetryPromptPart means the tool refused and the model
    was asked to try again (a bad path, a schema violation), which is a
    different thing from the job failing and worth seeing separately.
    """
    from pydantic_ai.messages import RetryPromptPart, ToolCallPart, ToolReturnPart

    calls: dict[str, dict] = {}
    order: list[str] = []
    for message in messages:
        for part in getattr(message, "parts", []):
            if isinstance(part, ToolCallPart):
                # Structured output is delivered through pydantic-ai's own
                # output tool. That is the mechanism by which the model returns
                # its answer, not a tool it chose to use, and its arguments are
                # the job's whole output — already stored on the job. Recording
                # it would put noise in every schema'd job's trail and bury the
                # calls someone is actually looking for.
                if part.tool_name == _OUTPUT_TOOL_NAME:
                    continue
                key = part.tool_call_id or f"{part.tool_name}:{len(order)}"
                raw_args = part.args
                args = raw_args if isinstance(raw_args, str) else json.dumps(raw_args, default=str)
                calls[key] = {
                    "tool": part.tool_name,
                    "args": args[:TOOL_EVENT_ARG_CHARS],
                    "args_truncated": len(args) > TOOL_EVENT_ARG_CHARS,
                    "outcome": "pending",
                }
                order.append(key)
            elif isinstance(part, ToolReturnPart) and part.tool_call_id in calls:
                content = part.content
                calls[part.tool_call_id]["outcome"] = "ok"
                calls[part.tool_call_id]["result_chars"] = len(
                    content if isinstance(content, str) else json.dumps(content, default=str)
                )
            elif isinstance(part, RetryPromptPart) and part.tool_call_id in calls:
                detail = part.content
                calls[part.tool_call_id]["outcome"] = "retry"
                calls[part.tool_call_id]["detail"] = str(detail)[:TOOL_EVENT_ARG_CHARS]
    return [("tool_call", calls[key]) for key in order]


def _rejects_forced_tool_choice(error: ModelHTTPError) -> bool:
    """Whether a 400 means "this model cannot be made to call a tool".

    Structured output is asked for by forcing a tool call, which not every
    model accepts — and the ones that refuse reject the request outright
    rather than degrading. An agent with an output schema is then unusable on
    that model entirely, which is a poor answer from a platform whose whole
    premise is that the model is a per-version choice.

    Matched on the message because providers do not give this a code of its
    own; aggregators pass the upstream text through, so the same phrase
    arrives whichever vendor served it.
    """
    if error.status_code != 400:
        return False
    return "tool_choice" in str(error.body or error).lower()


def _calc_cost(usage: RunUsage, model_name: str) -> tuple[Decimal, bool]:
    """Returns (cost, priced). An unpriced model costs 0 and says so.

    genai-prices covers the vendors it knows; a model it has no entry for
    raises, and treating that as free is not harmless. Monthly spending limits
    are enforced against accumulated cost, so an unpriced model spends real
    money against a budget that never moves and never refuses a job — the
    limit is silently inert for exactly the models nobody has checked.

    Still returns zero rather than failing the job: a gap in a pricing table
    is not a reason to refuse work. The caller records that the number is
    unknown instead of merely low.
    """
    try:
        from genai_prices import calc_price

        return Decimal(str(calc_price(usage, model_ref=model_name).total_price)), True
    except Exception:
        return Decimal(0), False


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


async def execute_job(
    job_id: uuid.UUID, *, sync_cap: bool = False, prompted_output: bool = False
) -> None:
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
    def _build_agent(prompted: bool) -> PaiAgent:
        """The same agent, differing only in how structured output is asked for.

        Tool output is the better mode where it works — the schema is enforced
        by the provider rather than by parsing prose — so it stays the default
        and prompted output is only reached by falling back.
        """
        if version.output_schema:
            schema = StructuredDict(version.output_schema)
            output_type = PromptedOutput(schema) if prompted else schema
        else:
            output_type = str
        return PaiAgent(
            model,
            instructions=instructions,
            output_type=output_type,
            model_settings=version.params or None,
            toolsets=toolsets or None,
            # Retries stay above the request cap so max_iterations is the
            # binding guardrail (UsageLimitExceeded → iteration_limit, a
            # first-class status).
            retries=version.max_iterations,
        )

    pai_agent = _build_agent(prompted=prompted_output)
    limits = UsageLimits(request_limit=version.max_iterations)
    timeout_s = version.timeout_s
    if sync_cap:
        timeout_s = min(timeout_s, get_settings().sync_job_timeout_s)

    status = "succeeded"
    output: dict | None = None
    error: str | None = None
    usage: RunUsage | None = None
    events: list[tuple[str, dict]] = []
    # Held outside the `async with` so the tool trail survives an exception
    # raised inside it — a job that dies in a tool is exactly the one whose
    # tool calls you need to see.
    run_messages: list = []
    try:
        async with asyncio.timeout(timeout_s):
            # iter() instead of run(): between model calls, check the cost
            # accrued so far against what's left of the monthly budget, so a
            # runaway job is bounded by $ and not only by iterations/timeout.
            async with pai_agent.iter(user_content, usage_limits=limits) as agent_run:
                async for _node in agent_run:
                    # Refreshed before the budget guard, not after: with no
                    # spending limit that guard `continue`s, which is the
                    # common case and would leave the trail empty.
                    run_messages = agent_run.all_messages()
                    if remaining_budget is None:
                        continue
                    run_cost, _priced = _calc_cost(agent_run.usage, model_row.name)
                    if run_cost >= remaining_budget:
                        usage = agent_run.usage
                        raise _BudgetExceededMidRun(
                            f"mid-run cost {run_cost} reached the remaining monthly "
                            f"budget {remaining_budget}"
                        )
                result = agent_run.result
                run_messages = agent_run.all_messages()
        raw = result.output
        output = raw if isinstance(raw, dict) else {"text": raw}
        usage = result.usage
    except _BudgetExceededMidRun as e:
        status, error = "budget_exceeded", str(e)
    except TimeoutError:
        status, error = "timeout", f"Job exceeded wall-clock timeout of {timeout_s}s"
    except asyncio.CancelledError:
        # Cancelled from outside. CancelledError is BaseException, so without
        # this clause the job would be stranded in `running` forever.
        await _handle_cancellation(job_id)
        raise  # so the canceller's own control flow proceeds
    except UsageLimitExceeded as e:
        status, error = "iteration_limit", str(e)
    except ModelHTTPError as e:
        if e.status_code == 429 or e.status_code >= 500:
            await _record_event(job_id, "transient_error", {"error": str(e)})
            raise TransientJobError(str(e)) from e
        if _rejects_forced_tool_choice(e) and version.output_schema and not prompted_output:
            # Ask for the schema in the prompt instead. Recorded rather than
            # silent: the same agent is now getting its structure from parsed
            # prose, which is worth knowing when comparing runs across models.
            # Written now, not appended: the retry finalizes the job and this
            # frame's events never reach it.
            await _record_event(
                job_id, "output_mode_fallback", {"from": "tool", "to": "prompted"}
            )
            return await execute_job(job_id, sync_cap=sync_cap, prompted_output=True)
        status, error = "failed", str(e)
    except httpx.TransportError as e:
        await _record_event(job_id, "transient_error", {"error": str(e)})
        raise TransientJobError(str(e)) from e
    except Exception as e:
        status, error = "failed", f"{type(e).__name__}: {e}"

    events += _tool_call_events(run_messages)

    # An aggregator's real charge is knowable only from the aggregator: it
    # routes to whichever upstream is available and bills what that upstream
    # cost, which no static table can predict. Asked for only when there was a
    # run to pay for, and never allowed to affect the job's outcome.
    cost_override: Decimal | None = None
    if model_row.provider == "openrouter" and run_messages:
        generation_ids = [
            message.provider_response_id
            for message in run_messages
            if getattr(message, "provider_response_id", None)
        ]
        cost_override = await fetch_openrouter_cost(api_key or "", generation_ids)

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
        provider=model_row.provider,
        cost_override=cost_override,
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
    provider: str | None = None,
    cost_override: Decimal | None = None,
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
            job.cost, priced = _calc_cost(usage, model_name)
            if cost_override is not None:
                # What the provider actually billed beats what a table guessed.
                job.cost, priced = cost_override, True
            # The keyless test provider is free on purpose, not unpriced.
            if not priced and provider != "test":
                logger.warning(
                    "no price for model %r — job %s cost recorded as 0, and this "
                    "agent's spending limit will not bind for it",
                    model_name,
                    job.id,
                )
                db.add(
                    JobEvent(
                        job_id=job.id,
                        type="cost_unpriced",
                        data={"model": model_name, "provider": provider},
                    )
                )
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


async def _handle_cancellation(job_id: uuid.UUID) -> None:
    """Put a job cancelled by a worker shutdown back on the queue.

    Two things cancel a job, and they want opposite outcomes. A delegated
    child runs inside its parent's task — delegation calls execute_job
    directly rather than enqueuing — so a parent timeout only ever cancels a
    job that has a parent, and that child was never on the queue for anything
    to redeliver. It failed, and its parent is gone.

    A top-level job has no such canceller: only the worker going away stops
    it. arq already redelivers that one ("cancelled, will be run again" —
    retry_jobs defaults to True). Marking it failed made the redelivery
    useless, because execute_job returns immediately unless the row is queued
    or running: the job came back and was dropped by our own guard. Nothing
    was wrong with it, so leave it runnable and let arq bring it back.

    This matters wherever deploys are routine. Every push that restarts the
    worker killed whatever was mid-flight, permanently, and the only sign was
    a job marked failed with no error a human could act on.
    """
    async with get_sessionmaker()() as db:
        job = await db.get(Job, job_id)
        if job is None:
            return
        if job.parent_job_id is not None:
            await _finalize(job_id, "failed", error="cancelled: the calling job ended first")
            return
        job.status = "queued"
        job.started_at = None
        db.add(
            JobEvent(
                job_id=job.id,
                type="requeued",
                data={"reason": "worker shut down mid-run"},
            )
        )
        await db.commit()


async def _record_event(job_id: uuid.UUID, event_type: str, data: dict) -> None:
    async with get_sessionmaker()() as db:
        db.add(JobEvent(job_id=job_id, type=event_type, data=data))
        await db.commit()


async def mark_job(job_id: uuid.UUID, status: str, error: str | None = None) -> None:
    """Terminal bookkeeping from outside the runner (retry exhaustion, etc.)."""
    await _finalize(job_id, status, error=error)
