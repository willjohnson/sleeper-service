"""Org- and team-level system prompts: versioned, pinned on every job.

The prompt sandwich is tenant (org) prompt → team prompt → agent prompt →
memory, and a job records the exact tenant and team prompt versions it ran
with, so agent version + prompt versions + memory version reproduce it.
"""

import uuid

import pytest
from httpx import AsyncClient
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from sqlalchemy import update

from sleeper_service.db.models import Job, MemoryVersion
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import runner
from tests.conftest import Bootstrap, auth


def _capturing_model(captured: list[str]):
    """A model that records the instructions it was given and answers."""

    def factory(*_args) -> FunctionModel:
        def respond(messages: list, info: AgentInfo) -> ModelResponse:
            requests = [m for m in messages if isinstance(m, ModelRequest)]
            captured.append(requests[-1].instructions or "")
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


async def _submit(client: AsyncClient, headers: dict, agent_id: str) -> str:
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=headers, json={"context": {"prompt": "assess"}}
    )
    assert r.status_code == 202, r.text
    return r.json()["id"]


async def _set_tenant_prompt(client, headers, tenant_id, text) -> None:
    r = await client.patch(
        f"/v1/tenants/{tenant_id}", headers=headers, json={"system_prompt": text}
    )
    assert r.status_code == 200, r.text


async def _set_team_prompt(client, headers, team_id, text) -> None:
    r = await client.patch(f"/v1/teams/{team_id}", headers=headers, json={"system_prompt": text})
    assert r.status_code == 200, r.text


async def test_sandwich_layers_tenant_team_agent_memory_in_order(
    client: AsyncClient,
    bootstrap: Bootstrap,
    risk_agent: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    await _set_tenant_prompt(client, root, risk_agent["tenant"]["id"], "ORG: house style.")
    await _set_team_prompt(client, alice, risk_agent["team"]["id"], "TEAM: risk conventions.")
    r = await client.patch(
        f"/v1/agents/{agent_id}", headers=alice, json={"options": {"memory": True}}
    )
    assert r.status_code == 200
    async with get_sessionmaker()() as db:
        db.add(MemoryVersion(agent_id=uuid.UUID(agent_id), version_no=1, content="MEMORY: notes."))
        await db.commit()

    captured: list[str] = []
    monkeypatch.setattr(runner, "build_model", _capturing_model(captured))
    await runner.execute_job(uuid.UUID(await _submit(client, bob, agent_id)))

    instructions = captured[0]
    positions = [
        instructions.index(marker)
        for marker in (
            "ORG: house style.",
            "TEAM: risk conventions.",
            "Assess business risk",
            "MEMORY: notes.",
        )
    ]
    assert positions == sorted(positions)


async def test_job_pins_the_prompt_versions_it_ran_with(
    client: AsyncClient,
    bootstrap: Bootstrap,
    risk_agent: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]
    team_id = risk_agent["team"]["id"]

    await _set_tenant_prompt(client, root, tenant_id, "org v1")
    await _set_tenant_prompt(client, root, tenant_id, "org v2")
    await _set_team_prompt(client, alice, team_id, "team v1")

    monkeypatch.setattr(runner, "build_model", _capturing_model([]))
    job_id = await _submit(client, bob, risk_agent["agent"]["id"])
    await runner.execute_job(uuid.UUID(job_id))

    tenant_history = (
        await client.get(f"/v1/tenants/{tenant_id}/prompt-versions", headers=bob)
    ).json()
    team_history = (await client.get(f"/v1/teams/{team_id}/prompt-versions", headers=bob)).json()
    job = (await client.get(f"/v1/jobs/{job_id}", headers=bob)).json()
    assert job["tenant_prompt_version_id"] == tenant_history[0]["id"]
    assert tenant_history[0]["content"] == "org v2"
    assert job["team_prompt_version_id"] == team_history[0]["id"]


async def test_job_without_prompts_pins_nothing(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    monkeypatch.setattr(runner, "build_model", _capturing_model([]))
    job_id = await _submit(client, bob, risk_agent["agent"]["id"])
    await runner.execute_job(uuid.UUID(job_id))

    job = (await client.get(f"/v1/jobs/{job_id}", headers=bob)).json()
    assert job["status"] == "succeeded"
    assert job["tenant_prompt_version_id"] is None
    assert job["team_prompt_version_id"] is None


async def test_rerun_of_a_started_job_keeps_its_pinned_prompts(
    client: AsyncClient,
    bootstrap: Bootstrap,
    risk_agent: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry re-enters execute_job with the job already running; it must
    run under the prompts pinned on the first attempt, not whatever has been
    saved since — including "no prompt" when none existed then."""
    root = auth(bootstrap.superuser_key)
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]

    await _set_tenant_prompt(client, root, tenant_id, "org first")
    pinned_tenant = (
        await client.get(f"/v1/tenants/{tenant_id}/prompt-versions", headers=bob)
    ).json()[0]["id"]
    job_id = await _submit(client, bob, risk_agent["agent"]["id"])
    async with get_sessionmaker()() as db:
        await db.execute(
            update(Job)
            .where(Job.id == uuid.UUID(job_id))
            .values(status="running", tenant_prompt_version_id=uuid.UUID(pinned_tenant))
        )
        await db.commit()

    await _set_tenant_prompt(client, root, tenant_id, "org second")
    await _set_team_prompt(client, alice, risk_agent["team"]["id"], "team added later")

    captured: list[str] = []
    monkeypatch.setattr(runner, "build_model", _capturing_model(captured))
    await runner.execute_job(uuid.UUID(job_id))

    assert "org first" in captured[0]
    assert "org second" not in captured[0]
    assert "team added later" not in captured[0]
    job = (await client.get(f"/v1/jobs/{job_id}", headers=bob)).json()
    assert job["tenant_prompt_version_id"] == pinned_tenant
    assert job["team_prompt_version_id"] is None


async def test_only_team_owners_edit_the_team_prompt(client: AsyncClient, risk_agent: dict) -> None:
    team_id = risk_agent["team"]["id"]
    users = risk_agent["users"]

    for name, expected in (("bob", 403), ("carol", 403), ("dave", 404)):
        r = await client.patch(
            f"/v1/teams/{team_id}",
            headers=auth(users[name]["api_key"]),
            json={"system_prompt": f"from {name}"},
        )
        assert r.status_code == expected, (name, r.text)

    alice = auth(users["alice"]["api_key"])
    r = await client.patch(f"/v1/teams/{team_id}", headers=alice, json={"system_prompt": "ok"})
    assert r.status_code == 200
    assert r.json()["system_prompt"] == "ok"

    # members of any role can read it, and its history
    carol = auth(users["carol"]["api_key"])
    assert (await client.get(f"/v1/teams/{team_id}", headers=carol)).json()["system_prompt"] == "ok"
    r = await client.get(f"/v1/teams/{team_id}/prompt-versions", headers=carol)
    assert r.status_code == 200
    assert [v["content"] for v in r.json()] == ["ok"]
    r = await client.get(
        f"/v1/teams/{team_id}/prompt-versions", headers=auth(users["dave"]["api_key"])
    )
    assert r.status_code == 404


async def test_every_change_is_a_new_version_and_unchanged_saves_are_not(
    client: AsyncClient, bootstrap: Bootstrap, org: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(org["users"]["alice"]["api_key"])
    tenant_id = org["tenant"]["id"]

    for text in ("first", "first", "second", ""):
        await _set_tenant_prompt(client, root, tenant_id, text)
    # a settings-only update leaves the prompt alone
    r = await client.patch(f"/v1/tenants/{tenant_id}", headers=root, json={"settings": {}})
    assert r.status_code == 200

    history = (await client.get(f"/v1/tenants/{tenant_id}/prompt-versions", headers=alice)).json()
    assert [(v["version_no"], v["content"]) for v in history] == [
        (3, ""),
        (2, "second"),
        (1, "first"),
    ]
    assert history[0]["created_by"] == str(bootstrap.superuser_id)
    assert history[0]["team_id"] is None
    tenant = (await client.get(f"/v1/tenants/{tenant_id}", headers=alice)).json()
    assert tenant["system_prompt"] == ""


async def test_tenant_and_team_prompt_histories_are_separate(
    client: AsyncClient, bootstrap: Bootstrap, org: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(org["users"]["alice"]["api_key"])
    tenant_id = org["tenant"]["id"]
    team_id = org["team"]["id"]

    await _set_tenant_prompt(client, root, tenant_id, "org")
    await _set_team_prompt(client, alice, team_id, "team")

    tenant_history = (
        await client.get(f"/v1/tenants/{tenant_id}/prompt-versions", headers=alice)
    ).json()
    team_history = (await client.get(f"/v1/teams/{team_id}/prompt-versions", headers=alice)).json()
    assert [(v["version_no"], v["content"]) for v in tenant_history] == [(1, "org")]
    assert [(v["version_no"], v["content"], v["team_id"]) for v in team_history] == [
        (1, "team", team_id)
    ]
    assert (await client.get(f"/v1/tenants/{tenant_id}", headers=alice)).json()[
        "system_prompt"
    ] == "org"
    assert (await client.get(f"/v1/teams/{team_id}", headers=alice)).json()[
        "system_prompt"
    ] == "team"


async def test_tenant_created_with_a_prompt_starts_at_version_one(
    client: AsyncClient, bootstrap: Bootstrap
) -> None:
    root = auth(bootstrap.superuser_key)
    r = await client.post(
        "/v1/tenants", headers=root, json={"name": "globex", "system_prompt": "Be terse."}
    )
    assert r.status_code == 201
    assert r.json()["system_prompt"] == "Be terse."
    history = (
        await client.get(f"/v1/tenants/{r.json()['id']}/prompt-versions", headers=root)
    ).json()
    assert [(v["version_no"], v["content"]) for v in history] == [(1, "Be terse.")]


async def test_demo_tenant_is_seeded_with_its_prompt_once(
    client: AsyncClient, bootstrap: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fsspec

    from sleeper_service.cli.main import _demo_setup

    # The seed also writes a playbook to object storage; keep that off the
    # developer's MinIO.
    memory_fs = fsspec.filesystem("memory")
    monkeypatch.setattr(fsspec, "filesystem", lambda *_a, **_k: memory_fs)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    await _demo_setup()
    await _demo_setup()  # idempotent: re-running adds no versions

    root = auth(bootstrap.superuser_key)
    tenants = (await client.get("/v1/tenants", headers=root)).json()
    demo = next(t for t in tenants if t["name"] == "demo")
    assert demo["system_prompt"] == "Be concise and factual."
    history = (await client.get(f"/v1/tenants/{demo['id']}/prompt-versions", headers=root)).json()
    assert [v["version_no"] for v in history] == [1]


async def test_manual_retry_of_a_failed_job_runs_under_the_live_prompts(
    client: AsyncClient,
    bootstrap: Bootstrap,
    risk_agent: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A person retrying a failed job is asking for a fresh run now: it picks
    up prompt fixes saved since, and the job records the versions it reran
    with. (Automatic worker retries keep the first attempt's pins — see
    test_rerun_of_a_started_job_keeps_its_pinned_prompts.)"""
    root = auth(bootstrap.superuser_key)
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]

    await _set_tenant_prompt(client, root, tenant_id, "org broken")
    monkeypatch.setattr(runner, "build_model", _capturing_model([]))
    job_id = await _submit(client, bob, risk_agent["agent"]["id"])
    await runner.execute_job(uuid.UUID(job_id))
    await runner.mark_job(uuid.UUID(job_id), "failed", "bad output")

    await _set_tenant_prompt(client, root, tenant_id, "org fixed")
    r = await client.post(f"/v1/jobs/{job_id}/retry", headers=bob)
    assert r.status_code == 202

    captured: list[str] = []
    monkeypatch.setattr(runner, "build_model", _capturing_model(captured))
    await runner.execute_job(uuid.UUID(job_id))

    assert "org fixed" in captured[0]
    assert "org broken" not in captured[0]
    live = (await client.get(f"/v1/tenants/{tenant_id}/prompt-versions", headers=bob)).json()[0]
    job = (await client.get(f"/v1/jobs/{job_id}", headers=bob)).json()
    assert job["tenant_prompt_version_id"] == live["id"]
