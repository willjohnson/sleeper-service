"""Eval harness (BUILD_PLAN § Eval design).

A test case is a saved job input plus a list of checks; because agent outputs
are typed JSON, grading is deterministic and free. Eval jobs run through the
normal pipeline — hooks and tracing apply — but are flagged is_eval: no
callbacks, excluded from spend rollups, exempt from budget refusal.

Check format ({"path": "risk_level", "op": ..., "value": ...}):
- equals        output[path] == value
- contains      value in output[path] (string or array)
- in_range      value = [min, max], inclusive
- matches_regex re.search(value, str(output[path]))
- is_valid      output validates against the version's output_schema (no path)
- code          {"op": "code", "code": "def grade(output): ..."} — grade(output)
                runs in the sandbox (runtime/sandbox.py); truthy return = pass

The eval gate: a pending memory version (memory_approval governance) with an
eval suite triggers a run pinned to that memory; a pass rate below the last
completed run for the same agent version alerts the owning team.
"""

import re
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import anyio
import jsonschema
from sqlalchemy import func, select

from sleeper_service.db.models import Agent, AgentVersion, EvalCase, EvalRun, Job
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import notify, sandbox

VALID_OPS = {"equals", "contains", "in_range", "matches_regex", "is_valid", "code"}
PATH_OPS = {"equals", "contains", "in_range", "matches_regex"}

# Validation runs editor-supplied top-level statements at case-creation time,
# in the API process — keep the cap tight so a hostile def can't stall a route
GRADER_VALIDATE_LIMITS = {**sandbox.DEFAULT_LIMITS, "max_duration_secs": 1.0}


def _dig(output: Any, path: str) -> Any:
    value = output
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def run_check(check: dict, output: dict | None, output_schema: dict | None) -> tuple[bool, str]:
    """Returns (passed, detail)."""
    op = check.get("op")
    if output is None:
        return False, "no output to check"
    if op == "is_valid":
        if not output_schema:
            return False, "is_valid requires the version to declare an output_schema"
        try:
            jsonschema.validate(output, output_schema)
            return True, "output matches schema"
        except jsonschema.ValidationError as e:
            return False, f"schema violation: {e.message}"

    if op == "code":
        try:
            result = sandbox.run_function(check.get("code", ""), "grade", output)
        except sandbox.SandboxError as e:
            return False, f"grader error: {e}"
        return bool(result), f"grade(output) -> {result!r}"

    path = check.get("path", "")
    actual = _dig(output, path)
    value = check.get("value")
    if op == "equals":
        return actual == value, f"{path}={actual!r}, expected {value!r}"
    if op == "contains":
        try:
            ok = value in actual
        except TypeError:
            ok = False
        return ok, f"{path}={actual!r}, expected to contain {value!r}"
    if op == "in_range":
        try:
            lo, hi = value
            ok = actual is not None and lo <= actual <= hi
        except (TypeError, ValueError):
            ok = False
        return ok, f"{path}={actual!r}, expected within {value!r}"
    if op == "matches_regex":
        ok = actual is not None and re.search(str(value), str(actual)) is not None
        return ok, f"{path}={actual!r}, expected to match /{value}/"
    return False, f"unknown op {op!r}"


def validate_checks(checks: list) -> str | None:
    """May block for up to GRADER_VALIDATE_LIMITS on code checks — async
    callers should offload to a thread."""
    if not checks:
        return "at least one check is required"
    for check in checks:
        if not isinstance(check, dict) or check.get("op") not in VALID_OPS:
            return f"invalid check {check!r}; ops: {sorted(VALID_OPS)}"
        op = check["op"]
        if op in PATH_OPS and not check.get("path"):
            return f"check {check!r} requires a path"
        if op in PATH_OPS and "value" not in check:
            return f"check {check!r} requires a value"
        if op == "code":
            code = check.get("code")
            if not isinstance(code, str) or not code.strip():
                return "code check requires a 'code' string defining grade(output)"
            detail = sandbox.validate_function(code, "grade", limits=GRADER_VALIDATE_LIMITS)
            if detail is not None:
                return f"invalid grader: {detail}"
    return None


def _grade_output(checks: list, output: dict | None, output_schema: dict | None) -> list[dict]:
    return [
        {"check": check, "passed": ok, "detail": detail}
        for check in checks
        for ok, detail in [run_check(check, output, output_schema)]
    ]


async def run_eval(eval_run_id: uuid.UUID) -> None:
    """Execute every case for the run's agent, grade, store results.
    Sequential on purpose: suites are small and provider-friendly."""
    from sleeper_service.runtime import runner as runner_mod

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db:
        run = await db.get(EvalRun, eval_run_id)
        if run is None or run.status != "running":
            return
        version = await db.get(AgentVersion, run.agent_version_id)
        cases = list(
            await db.scalars(
                select(EvalCase).where(EvalCase.agent_id == run.agent_id).order_by(EvalCase.name)
            )
        )

    results = []
    passed_cases = 0
    for case in cases:
        async with sessionmaker() as db:
            job = Job(
                agent_id=run.agent_id,
                agent_version_id=run.agent_version_id,
                memory_version_id=run.memory_version_id,
                payload=case.input,
                is_eval=True,
            )
            db.add(job)
            await db.commit()
            job_id = job.id

        try:
            await runner_mod.execute_job(job_id)
        except runner_mod.TransientJobError as e:
            await runner_mod.mark_job(job_id, "failed", f"transient provider error: {e}")

        async with sessionmaker() as db:
            job = await db.get(Job, job_id)

        if job.status == "succeeded":
            # in a thread: code graders hold the (GIL-released) call for up
            # to their duration cap
            check_results = await anyio.to_thread.run_sync(
                _grade_output, case.checks, job.output, version.output_schema
            )
        else:
            check_results = [
                {
                    "check": check,
                    "passed": False,
                    "detail": f"job {job.status}: {job.error}",
                }
                for check in case.checks
            ]
        case_passed = all(r["passed"] for r in check_results)
        passed_cases += case_passed
        results.append(
            {
                "case_id": str(case.id),
                "case_name": case.name,
                "job_id": str(job_id),
                "job_status": job.status,
                "passed": case_passed,
                "checks": check_results,
            }
        )

    pass_rate = Decimal(passed_cases) / Decimal(len(cases)) if cases else Decimal(0)
    async with sessionmaker() as db:
        # baseline: the most recent completed run for the same agent version
        baseline = await db.scalar(
            select(EvalRun)
            .where(
                EvalRun.agent_id == run.agent_id,
                EvalRun.agent_version_id == run.agent_version_id,
                EvalRun.status == "completed",
                EvalRun.id != run.id,
            )
            .order_by(EvalRun.created_at.desc())
            .limit(1)
        )
        run = await db.get(EvalRun, eval_run_id)
        run.results = results
        run.pass_rate = pass_rate
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        await db.commit()

    if baseline is not None and baseline.pass_rate is not None and pass_rate < baseline.pass_rate:
        async with sessionmaker() as db:
            agent = await db.get(Agent, run.agent_id)
        await notify.notify(
            run.agent_id,
            "eval_regression",
            f"Sleeper Service: eval regression — {agent.name}",
            f"Eval run {eval_run_id} scored {pass_rate:.0%} "
            f"(baseline {baseline.pass_rate:.0%})."
            + (
                " This run gates a PENDING memory version — review before approving."
                if run.memory_version_id
                else ""
            ),
        )


async def maybe_trigger_memory_eval(agent_id: uuid.UUID, memory_version_id: uuid.UUID) -> None:
    """The eval gate: a pending memory version triggers the agent's suite,
    pinned to that memory, so lessons get verified before approval."""
    async with get_sessionmaker()() as db:
        agent = await db.get(Agent, agent_id)
        case_count = await db.scalar(
            select(func.count()).select_from(EvalCase).where(EvalCase.agent_id == agent_id)
        )
        if agent is None or agent.current_version_id is None or not case_count:
            return
        run = EvalRun(
            agent_id=agent_id,
            agent_version_id=agent.current_version_id,
            memory_version_id=memory_version_id,
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    from sleeper_service.queue import get_pool

    pool = await get_pool()
    await pool.enqueue_job("run_eval", str(run_id))
