"""Eval harness + learning governance."""

import uuid

import pytest
from httpx import AsyncClient
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from sleeper_service.runtime import runner
from sleeper_service.runtime.evals import run_check, run_eval, validate_checks
from tests.conftest import RISK_SCHEMA, auth

# --- Check engine (unit) ---


def test_check_ops() -> None:
    output = {"risk_level": "high", "factors": ["weather", "staffing"], "score": 7}
    assert run_check({"op": "equals", "path": "risk_level", "value": "high"}, output, None)[0]
    assert not run_check({"op": "equals", "path": "risk_level", "value": "low"}, output, None)[0]
    assert run_check({"op": "contains", "path": "factors", "value": "weather"}, output, None)[0]
    assert not run_check({"op": "contains", "path": "factors", "value": "aliens"}, output, None)[0]
    assert run_check({"op": "in_range", "path": "score", "value": [5, 10]}, output, None)[0]
    assert not run_check({"op": "in_range", "path": "score", "value": [8, 10]}, output, None)[0]
    assert run_check({"op": "matches_regex", "path": "risk_level", "value": "^hi"}, output, None)[0]
    ok, detail = run_check(
        {"op": "is_valid"}, {"risk_level": "high", "factors": [], "summary": "x"}, RISK_SCHEMA
    )
    assert ok, detail
    ok, _ = run_check({"op": "is_valid"}, {"risk_level": "extreme"}, RISK_SCHEMA)
    assert not ok
    assert run_check({"op": "equals", "path": "missing.deep", "value": 1}, output, None)[0] is False

    assert validate_checks([]) is not None
    assert validate_checks([{"op": "explode"}]) is not None
    assert validate_checks([{"op": "equals", "path": "x"}]) is not None  # no value
    assert validate_checks([{"op": "equals", "path": "x", "value": 1}]) is None
    assert validate_checks([{"op": "is_valid"}]) is None


# --- Eval runs ---


@pytest.fixture
async def eval_cases(client: AsyncClient, risk_agent: dict) -> dict:
    """Two cases: TestModel emits risk_level='low' and factors=['a'], so one
    case passes and one fails by construction."""
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    passing = {
        "name": "01-low-risk",
        "input": {"prompt": "calm markets today"},
        "checks": [
            {"op": "equals", "path": "risk_level", "value": "low"},
            {"op": "is_valid"},
        ],
    }
    failing = {
        "name": "02-expects-high",
        "input": {"prompt": "AAPL down 9%, storm in STL"},
        "checks": [{"op": "equals", "path": "risk_level", "value": "high"}],
    }
    for case in (passing, failing):
        r = await client.post(f"/v1/agents/{agent_id}/eval-cases", headers=bob, json=case)
        assert r.status_code == 201
    return risk_agent


async def test_eval_run_end_to_end(client: AsyncClient, eval_cases: dict) -> None:
    bob = auth(eval_cases["users"]["bob"]["api_key"])
    carol = auth(eval_cases["users"]["carol"]["api_key"])
    agent_id = eval_cases["agent"]["id"]

    # viewers cannot manage cases or start runs
    r = await client.post(f"/v1/agents/{agent_id}/eval-runs", headers=carol, json={})
    assert r.status_code == 403

    r = await client.post(f"/v1/agents/{agent_id}/eval-runs", headers=bob, json={})
    assert r.status_code == 202
    run_id = r.json()["id"]

    await run_eval(uuid.UUID(run_id))  # as the worker would

    r = await client.get(f"/v1/agents/{agent_id}/eval-runs/{run_id}", headers=carol)
    run = r.json()
    assert run["status"] == "completed"
    assert float(run["pass_rate"]) == 0.5
    by_name = {res["case_name"]: res for res in run["results"]}
    assert by_name["01-low-risk"]["passed"] is True
    assert by_name["02-expects-high"]["passed"] is False
    assert "expected 'high'" in by_name["02-expects-high"]["checks"][0]["detail"]

    # eval jobs never count against production spend
    spend = (await client.get(f"/v1/agents/{agent_id}/spend", headers=bob)).json()
    assert float(spend["spend"]) == 0


async def test_eval_run_version_pinning(client: AsyncClient, eval_cases: dict) -> None:
    bob = auth(eval_cases["users"]["bob"]["api_key"])
    agent_id = eval_cases["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={"prompt": "v2 prompt", "model": "test/default", "output_schema": RISK_SCHEMA},
    )
    v2 = r.json()
    r = await client.post(
        f"/v1/agents/{agent_id}/eval-runs", headers=bob, json={"version_no": 2}
    )
    assert r.status_code == 202
    assert r.json()["agent_version_id"] == v2["id"]

    r = await client.post(
        f"/v1/agents/{agent_id}/eval-runs", headers=bob, json={"version_no": 99}
    )
    assert r.status_code == 422


async def test_invalid_checks_rejected(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/eval-cases",
        headers=bob,
        json={"name": "bad", "input": {"prompt": "x"}, "checks": [{"op": "vibes"}]},
    )
    assert r.status_code == 422


# --- Governance: owner-gated toggles ---


async def test_learning_toggles_require_owner(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    # editor: ungoverned options fine, governed options forbidden
    r = await client.patch(
        f"/v1/agents/{agent_id}", headers=bob, json={"options": {"delegation": "team"}}
    )
    assert r.status_code == 200
    for opts in ({"memory": True}, {"learning": True}, {"memory_approval": True}):
        r = await client.patch(f"/v1/agents/{agent_id}", headers=bob, json={"options": opts})
        assert r.status_code == 403, f"editor toggled {opts}"

    # owner can
    r = await client.patch(
        f"/v1/agents/{agent_id}",
        headers=alice,
        json={"options": {"memory": True, "learning": True, "memory_approval": True}},
    )
    assert r.status_code == 200

    # editor also cannot silently drop them
    r = await client.patch(f"/v1/agents/{agent_id}", headers=bob, json={"options": {}})
    assert r.status_code == 403

    # creating an agent with governed options on also requires owner
    r = await client.post(
        "/v1/agents",
        headers=bob,
        json={"team_id": risk_agent["team"]["id"], "name": "sneaky-learner",
              "options": {"learning": True}},
    )
    assert r.status_code == 403


# --- Approval workflow ---


def _memory_writer_model(note: str):
    def factory(*_args) -> FunctionModel:
        def respond(messages: list, info: AgentInfo) -> ModelResponse:
            seen = [
                p.tool_name
                for m in messages
                for p in getattr(m, "parts", [])
                if isinstance(p, ToolCallPart)
            ]
            if "update_memory" not in seen:
                return ModelResponse(
                    parts=[ToolCallPart(tool_name="update_memory", args={"new_content": note})]
                )
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        tool_name="final_result",
                        args={"risk_level": "low", "factors": [], "summary": "ok"},
                    )
                ]
            )

        return FunctionModel(respond)

    return factory


async def test_memory_approval_flow(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.patch(
        f"/v1/agents/{agent_id}",
        headers=alice,
        json={"options": {"memory": True, "memory_approval": True}},
    )
    assert r.status_code == 200

    note = "# Notes\nAlways cross-check staffing numbers."
    monkeypatch.setattr(runner, "build_model", _memory_writer_model(note))
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=bob, json={"context": {"prompt": "assess"}}
    )
    job1 = r.json()["id"]
    await runner.execute_job(uuid.UUID(job1))

    # pending, not injected
    mem = (await client.get(f"/v1/agents/{agent_id}/memory", headers=bob)).json()
    assert mem["current"] is None
    pending = (await client.get(f"/v1/agents/{agent_id}/memory/pending", headers=bob)).json()
    assert len(pending) == 1
    version_no = pending[0]["version"]["version_no"]
    assert pending[0]["version"]["content"] == note
    events = (await client.get(f"/v1/jobs/{job1}/events", headers=bob)).json()
    assert "memory_update_pending" in [e["type"] for e in events]

    # editor/viewer cannot approve; owner can
    for headers in (bob, carol):
        r = await client.post(
            f"/v1/agents/{agent_id}/memory/{version_no}/approve", headers=headers
        )
        assert r.status_code == 403
    r = await client.post(f"/v1/agents/{agent_id}/memory/{version_no}/approve", headers=alice)
    assert r.status_code == 200

    mem = (await client.get(f"/v1/agents/{agent_id}/memory", headers=bob)).json()
    assert mem["current"]["content"] == note

    # second proposal → reject → stays out
    note2 = "# Notes\nOnly weekend events matter."
    monkeypatch.setattr(runner, "build_model", _memory_writer_model(note2))
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=bob, json={"context": {"prompt": "assess again"}}
    )
    await runner.execute_job(uuid.UUID(r.json()["id"]))
    pending = (await client.get(f"/v1/agents/{agent_id}/memory/pending", headers=bob)).json()
    assert len(pending) == 1
    v2_no = pending[0]["version"]["version_no"]
    r = await client.post(f"/v1/agents/{agent_id}/memory/{v2_no}/reject", headers=alice)
    assert r.status_code == 200
    mem = (await client.get(f"/v1/agents/{agent_id}/memory", headers=bob)).json()
    assert mem["current"]["content"] == note  # still v1

    # rollback retires v1 → no active memory remains
    r = await client.post(f"/v1/agents/{agent_id}/memory/rollback", headers=alice)
    assert r.json()["now_active_version_no"] is None
    mem = (await client.get(f"/v1/agents/{agent_id}/memory", headers=bob)).json()
    assert mem["current"] is None


async def test_feedback_fold_lands_pending_under_approval(
    client: AsyncClient, risk_agent: dict
) -> None:
    from sleeper_service.runtime.learning import feedback_token, fold_feedback

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    await client.patch(
        f"/v1/agents/{agent_id}",
        headers=alice,
        json={"options": {"memory": True, "learning": True, "memory_approval": True}},
    )

    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=bob, json={"context": {"prompt": "assess"}}
    )
    job_id = r.json()["id"]
    await runner.execute_job(uuid.UUID(job_id))
    token = feedback_token(uuid.UUID(job_id))
    r = await client.post(
        f"/v1/feedback/{job_id}?token={token}",
        json={"vote": -1, "comment": "List staffing risks first."},
    )
    await fold_feedback(uuid.UUID(r.json()["id"]))

    mem = (await client.get(f"/v1/agents/{agent_id}/memory", headers=bob)).json()
    assert mem["current"] is None  # not live until approved
    pending = (await client.get(f"/v1/agents/{agent_id}/memory/pending", headers=bob)).json()
    # (TestModel also calls update_memory during the job, so the fold's version
    # is not necessarily the only pending one)
    assert any(
        "List staffing risks first." in entry["version"]["content"] for entry in pending
    )


# --- Eval gate ---


async def test_pending_memory_triggers_gating_eval_and_regression_alert(
    client: AsyncClient, eval_cases: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pending memory triggers the suite pinned to it; a worse pass rate
    than the version's baseline notifies the team."""
    from sleeper_service.db.models import EvalRun
    from sleeper_service.db.session import get_sessionmaker
    from sleeper_service.runtime import evals as evals_mod
    from sleeper_service.runtime import memory as memory_mod

    alice = auth(eval_cases["users"]["alice"]["api_key"])
    bob = auth(eval_cases["users"]["bob"]["api_key"])
    agent_id = eval_cases["agent"]["id"]
    await client.patch(
        f"/v1/agents/{agent_id}",
        headers=alice,
        json={"options": {"memory": True, "memory_approval": True}},
    )

    # baseline run: 50% (TestModel passes 1 of 2 cases)
    r = await client.post(f"/v1/agents/{agent_id}/eval-runs", headers=bob, json={})
    baseline_id = r.json()["id"]
    await run_eval(uuid.UUID(baseline_id))

    # pending memory write → gate run created (capture instead of enqueue)
    triggered: list[uuid.UUID] = []

    async def fake_enqueue(run_id):
        triggered.append(run_id)

    async def capture_trigger(agent_uuid, memory_version_id):
        async with get_sessionmaker()() as db:
            from sleeper_service.db.models import Agent

            agent = await db.get(Agent, agent_uuid)
            run = EvalRun(
                agent_id=agent_uuid,
                agent_version_id=agent.current_version_id,
                memory_version_id=memory_version_id,
            )
            db.add(run)
            await db.commit()
            triggered.append(run.id)

    monkeypatch.setattr(
        "sleeper_service.runtime.evals.maybe_trigger_memory_eval", capture_trigger
    )

    await memory_mod.write_memory(
        uuid.UUID(agent_id),
        "Bad lesson: everything is always fine, never flag high risk.",
        None,
        pending=True,
    )
    assert len(triggered) == 1
    gate_run_id = triggered[0]

    # make the gated run fail everything → regression vs 50% baseline
    def broken_model(*_args) -> FunctionModel:
        def respond(messages: list, info: AgentInfo) -> ModelResponse:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        tool_name="final_result",
                        args={"risk_level": "medium", "factors": [], "summary": "meh"},
                    )
                ]
            )

        return FunctionModel(respond)

    alerts: list[tuple] = []

    async def fake_notify(agent_uuid, event_type, title, body):
        alerts.append((event_type, body))

    monkeypatch.setattr(runner, "build_model", broken_model)
    monkeypatch.setattr(evals_mod.notify, "notify", fake_notify)

    await run_eval(gate_run_id)

    r = await client.get(f"/v1/agents/{agent_id}/eval-runs/{gate_run_id}", headers=bob)
    assert float(r.json()["pass_rate"]) == 0.0
    assert alerts and alerts[0][0] == "eval_regression"
    assert "PENDING memory" in alerts[0][1]

    # the pending queue shows the gating run's pass rate next to the version
    pending = (await client.get(f"/v1/agents/{agent_id}/memory/pending", headers=bob)).json()
    gated = next(
        entry for entry in pending if "Bad lesson" in entry["version"]["content"]
    )
    assert gated["eval_run"] is not None
    assert float(gated["eval_run"]["pass_rate"]) == 0.0
