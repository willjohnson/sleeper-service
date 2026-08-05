"""Phase 1: versions, jobs, runner guardrails, callbacks, rate limiting.

Runner tests execute jobs directly (as the worker would) with the `test`
provider or a monkeypatched FunctionModel — no vendor keys needed.
"""

import asyncio
import hashlib
import hmac
import json
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
from httpx import AsyncClient
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from sleeper_service.runtime import callbacks, runner
from sleeper_service.worker import deliver_callback, run_job
from tests.conftest import RISK_SCHEMA, Bootstrap, auth

# --- Versions ---


async def test_version_lifecycle(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    # first version auto-promoted
    r = await client.get(f"/v1/agents/{agent_id}", headers=bob)
    assert r.json()["current_version_id"] == risk_agent["version"]["id"]

    # viewer cannot create versions
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=carol,
        json={"prompt": "v2", "model": "test/default"},
    )
    assert r.status_code == 403

    # editor creates v2; current stays at v1
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={"prompt": "v2 prompt", "model": "test/default", "output_schema": RISK_SCHEMA},
    )
    assert r.status_code == 201
    v2 = r.json()
    assert v2["version_no"] == 2
    r = await client.get(f"/v1/agents/{agent_id}", headers=bob)
    assert r.json()["current_version_id"] == risk_agent["version"]["id"]

    # versions are immutable — there is no edit route
    r = await client.patch(
        f"/v1/agents/{agent_id}/versions/1", headers=bob, json={"prompt": "hacked"}
    )
    assert r.status_code == 405

    # editor cannot promote; owner can (and rollback works the same way)
    r = await client.post(f"/v1/agents/{agent_id}/promote", headers=bob, json={"version_no": 2})
    assert r.status_code == 403
    r = await client.post(f"/v1/agents/{agent_id}/promote", headers=alice, json={"version_no": 2})
    assert r.status_code == 200
    r = await client.get(f"/v1/agents/{agent_id}", headers=bob)
    assert r.json()["current_version_id"] == v2["id"]

    r = await client.post(f"/v1/agents/{agent_id}/promote", headers=alice, json={"version_no": 1})
    assert r.status_code == 200

    # unknown model rejected
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={"prompt": "v3", "model": "nope/nothing"},
    )
    assert r.status_code == 422


# --- Job submission & auth ---


async def _submit(client: AsyncClient, headers: dict, agent_id: str, **kwargs) -> httpx.Response:
    body = {"context": {"prompt": "AAPL down 6%; storm in STL"}, **kwargs}
    return await client.post(f"/v1/agents/{agent_id}/jobs", headers=headers, json=body)


async def test_submit_and_execute_async_job(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    r = await _submit(client, bob, agent_id)
    assert r.status_code == 202
    job = r.json()
    assert job["status"] == "queued"
    assert job["agent_version_id"] == risk_agent["version"]["id"]

    # execute as the worker would
    await runner.execute_job(uuid.UUID(job["id"]))

    r = await client.get(f"/v1/jobs/{job['id']}", headers=bob)
    done = r.json()
    assert done["status"] == "succeeded"
    assert set(done["output"]) == {"risk_level", "factors", "summary"}
    assert done["output"]["risk_level"] in ("low", "medium", "high")

    r = await client.get(f"/v1/jobs/{job['id']}/events", headers=bob)
    assert [e["type"] for e in r.json()] == ["submitted", "started", "finished"]


async def test_sync_job(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    r = await client.post(
        f"/v1/agents/{risk_agent['agent']['id']}/jobs?sync=true",
        headers=bob,
        json={"context": {"prompt": "quick check"}},
    )
    assert r.status_code == 202
    assert r.json()["status"] == "succeeded"
    assert r.json()["output"]["risk_level"] in ("low", "medium", "high")


async def test_job_auth_rules(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    dave = auth(risk_agent["users"]["dave"]["api_key"])
    alice = auth(risk_agent["users"]["alice"]["api_key"])

    # viewer cannot submit, outsider sees nothing
    assert (await _submit(client, carol, agent_id)).status_code == 403
    assert (await _submit(client, dave, agent_id)).status_code == 404

    # invoke key scoped to the agent can submit and read
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=alice,
        json={"scope": "agent", "scope_id": agent_id},
    )
    invoke = auth(r.json()["api_key"])
    r = await _submit(client, invoke, agent_id)
    assert r.status_code == 202
    job_id = r.json()["id"]
    assert (await client.get(f"/v1/jobs/{job_id}", headers=invoke)).status_code == 200

    # viewer can read jobs
    assert (await client.get(f"/v1/jobs/{job_id}", headers=carol)).status_code == 200

    # an invoke key for a different agent cannot touch this one
    r = await client.post(
        "/v1/agents",
        headers=auth(risk_agent["users"]["bob"]["api_key"]),
        json={"team_id": risk_agent["team"]["id"], "name": "other-agent"},
    )
    other_id = r.json()["id"]
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=alice,
        json={"scope": "agent", "scope_id": other_id},
    )
    other_invoke = auth(r.json()["api_key"])
    assert (await _submit(client, other_invoke, agent_id)).status_code == 404
    assert (await client.get(f"/v1/jobs/{job_id}", headers=other_invoke)).status_code == 404


async def test_idempotency_key_dedupes(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r1 = await _submit(client, bob, agent_id, idempotency_key="evt-42")
    r2 = await _submit(client, bob, agent_id, idempotency_key="evt-42")
    assert r1.json()["id"] == r2.json()["id"]


async def test_version_pinning(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={"prompt": "v2", "model": "test/default", "output_schema": RISK_SCHEMA},
    )
    v2 = r.json()

    # default: current version (v1); pinned: v2 by number and by id
    assert (await _submit(client, bob, agent_id)).json()["agent_version_id"] == risk_agent[
        "version"
    ]["id"]
    assert (await _submit(client, bob, agent_id, version_no=2)).json()["agent_version_id"] == v2[
        "id"
    ]
    assert (await _submit(client, bob, agent_id, agent_version_id=v2["id"])).json()[
        "agent_version_id"
    ] == v2["id"]
    r = await _submit(client, bob, agent_id, version_no=99)
    assert r.status_code == 422


async def test_version_aliases(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={"prompt": "v2", "model": "test/default", "output_schema": RISK_SCHEMA},
    )
    v2 = r.json()

    # editor cannot manage aliases; owner can
    r = await client.put(f"/v1/agents/{agent_id}/aliases/prod", headers=bob, json={"version_no": 1})
    assert r.status_code == 403
    r = await client.put(
        f"/v1/agents/{agent_id}/aliases/prod", headers=alice, json={"version_no": 1}
    )
    assert r.status_code == 200
    assert r.json()["version_no"] == 1

    # malformed alias names and unknown versions are rejected
    r = await client.put(
        f"/v1/agents/{agent_id}/aliases/Not%20Valid", headers=alice, json={"version_no": 1}
    )
    assert r.status_code == 422
    r = await client.put(
        f"/v1/agents/{agent_id}/aliases/staging", headers=alice, json={"version_no": 99}
    )
    assert r.status_code == 404

    # viewer can list
    r = await client.get(f"/v1/agents/{agent_id}/aliases", headers=carol)
    assert [(a["alias"], a["version_no"]) for a in r.json()] == [("prod", 1)]

    # submission pins by alias; promotion = repointing, picked up immediately
    r = await _submit(client, bob, agent_id, alias="prod")
    assert r.json()["agent_version_id"] == risk_agent["version"]["id"]
    r = await client.put(
        f"/v1/agents/{agent_id}/aliases/prod", headers=alice, json={"version_no": 2}
    )
    assert r.status_code == 200
    r = await _submit(client, bob, agent_id, alias="prod")
    assert r.json()["agent_version_id"] == v2["id"]

    # unknown alias and double pins are rejected
    assert (await _submit(client, bob, agent_id, alias="nope")).status_code == 422
    assert (await _submit(client, bob, agent_id, alias="prod", version_no=1)).status_code == 422

    # delete: owner only, then the alias no longer resolves
    assert (
        await client.delete(f"/v1/agents/{agent_id}/aliases/prod", headers=bob)
    ).status_code == 403
    assert (
        await client.delete(f"/v1/agents/{agent_id}/aliases/prod", headers=alice)
    ).status_code == 204
    assert (await _submit(client, bob, agent_id, alias="prod")).status_code == 422


async def test_agent_without_version_conflicts(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    r = await client.post(
        "/v1/agents",
        headers=bob,
        json={"team_id": risk_agent["team"]["id"], "name": "empty-agent"},
    )
    r = await _submit(client, bob, r.json()["id"])
    assert r.status_code == 409


# --- Runner guardrails ---


def _chatty_model(*_args) -> FunctionModel:
    """A model that never produces structured output — just keeps talking."""

    def respond(messages: list, info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[TextPart("still thinking...")])

    return FunctionModel(respond)


async def test_iteration_cap_kills_runaway_loop(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={
            "prompt": "loop forever",
            "model": "test/default",
            "output_schema": RISK_SCHEMA,
            "max_iterations": 2,
        },
    )
    v = r.json()
    monkeypatch.setattr(runner, "build_model", _chatty_model)

    r = await _submit(client, bob, agent_id, version_no=v["version_no"])
    job_id = uuid.UUID(r.json()["id"])
    await runner.execute_job(job_id)

    r = await client.get(f"/v1/jobs/{job_id}", headers=bob)
    assert r.json()["status"] == "iteration_limit"


async def test_timeout_guardrail(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={
            "prompt": "slow",
            "model": "test/default",
            "output_schema": RISK_SCHEMA,
            "timeout_s": 1,
        },
    )
    v = r.json()

    def slow_model(*_args) -> FunctionModel:
        async def respond(messages: list, info: AgentInfo) -> ModelResponse:
            await asyncio.sleep(5)
            return ModelResponse(parts=[TextPart("too late")])

        return FunctionModel(respond)

    monkeypatch.setattr(runner, "build_model", slow_model)

    r = await _submit(client, bob, agent_id, version_no=v["version_no"])
    job_id = uuid.UUID(r.json()["id"])
    await runner.execute_job(job_id)

    r = await client.get(f"/v1/jobs/{job_id}", headers=bob)
    body = r.json()
    assert body["status"] == "timeout"
    assert "1s" in body["error"]


# --- Worker retry / DLQ ---


async def test_transient_errors_retry_then_dead_letter(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arq import Retry

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    r = await _submit(client, bob, risk_agent["agent"]["id"])
    job_id = r.json()["id"]

    async def boom(job_uuid, **kwargs):
        raise runner.TransientJobError("provider 529")

    monkeypatch.setattr("sleeper_service.worker.execute_job", boom)

    with pytest.raises(Retry):
        await run_job({"job_try": 1, "redis": None}, job_id)

    from sleeper_service.config import get_settings

    await run_job({"job_try": get_settings().job_max_tries, "redis": None}, job_id)
    r = await client.get(f"/v1/jobs/{job_id}", headers=bob)
    assert r.json()["status"] == "dead_letter"
    assert "retries exhausted" in r.json()["error"]


# --- Callbacks ---


def test_signature_scheme() -> None:
    body = b'{"job_id": "x"}'
    header = callbacks.sign(body, 1700000000)
    assert header.startswith("t=1700000000,v1=")
    sig = header.split("v1=")[1]
    expected = hmac.new(b"test-secret-key", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert sig == expected


async def test_callback_delivery_and_retries(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await _submit(client, bob, agent_id, callback_url="https://receiver.example/hook")
    job_id = uuid.UUID(r.json()["id"])
    await runner.execute_job(job_id)

    received: list[httpx.Request] = []
    real_client = httpx.AsyncClient  # bind before patching to avoid recursion

    def make_client(**kwargs) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            received.append(request)
            return httpx.Response(200)

        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(callbacks.httpx, "AsyncClient", make_client)
    monkeypatch.setattr(callbacks, "validate_callback_target", AsyncMock())
    await deliver_callback({"job_try": 1}, str(job_id))

    assert len(received) == 1
    req = received[0]
    payload = json.loads(req.content)
    assert payload["status"] == "succeeded"
    assert payload["agent_version_id"] == risk_agent["version"]["id"]
    # verify signature like a receiver would
    t = req.headers["X-Sleeper-Signature"].split(",")[0].removeprefix("t=")
    v1 = req.headers["X-Sleeper-Signature"].split("v1=")[1]
    expected = hmac.new(
        b"test-secret-key", f"{t}.".encode() + req.content, hashlib.sha256
    ).hexdigest()
    assert v1 == expected

    r = await client.get(f"/v1/jobs/{job_id}/events", headers=bob)
    assert "callback_delivered" in [e["type"] for e in r.json()]

    # failing receiver → Retry, then gives up with an audit event
    from arq import Retry

    def failing_client(**kwargs) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(lambda req: httpx.Response(500)))

    monkeypatch.setattr(callbacks.httpx, "AsyncClient", failing_client)
    with pytest.raises(Retry):
        await deliver_callback({"job_try": 1}, str(job_id))

    from sleeper_service.config import get_settings

    await deliver_callback({"job_try": get_settings().callback_max_tries}, str(job_id))
    r = await client.get(f"/v1/jobs/{job_id}/events", headers=bob)
    assert "callback_failed" in [e["type"] for e in r.json()]


# --- Files ---


async def test_file_upload_and_job_reference(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]

    r = await client.post(
        f"/v1/files?tenant_id={tenant_id}",
        headers=bob,
        files={"file": ("notes.txt", b"reference data", "text/plain")},
    )
    assert r.status_code == 201
    file = r.json()
    assert file["size"] == len(b"reference data")

    r = await client.get(f"/v1/files/{file['id']}/content", headers=bob)
    assert r.content == b"reference data"

    r = await client.post(
        f"/v1/agents/{risk_agent['agent']['id']}/jobs",
        headers=bob,
        json={"context": {"prompt": "use the file", "files": [file["id"]]}},
    )
    assert r.status_code == 202
    await runner.execute_job(uuid.UUID(r.json()["id"]))
    r = await client.get(f"/v1/jobs/{r.json()['id']}", headers=bob)
    assert r.json()["status"] == "succeeded"

    # unknown file id rejected
    r = await client.post(
        f"/v1/agents/{risk_agent['agent']['id']}/jobs",
        headers=bob,
        json={"context": {"prompt": "x", "files": [str(uuid.uuid4())]}},
    )
    assert r.status_code == 422


# --- Rate limiting ---


async def test_rate_limited_key_gets_429(client: AsyncClient, risk_agent: dict) -> None:
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=alice,
        json={
            "scope": "agent",
            "scope_id": risk_agent["agent"]["id"],
            "rate_limit": 3,
        },
    )
    limited = auth(r.json()["api_key"])
    agent_id = risk_agent["agent"]["id"]

    codes = []
    for _ in range(5):
        resp = await client.get(f"/v1/agents/{agent_id}", headers=limited)
        codes.append(resp.status_code)
    # invoke keys get 403 on management reads — but the limiter fires first at 4
    assert codes[:3] == [403, 403, 403]
    assert codes[3] == 429
    assert codes[4] == 429


# --- Models registry permissions ---


async def test_models_registry_permissions(
    client: AsyncClient, bootstrap: Bootstrap, org: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(org["users"]["alice"]["api_key"])

    r = await client.post(
        "/v1/models",
        headers=alice,
        json={"provider": "test", "name": "x", "model_string": "test:x"},
    )
    assert r.status_code == 403
    r = await client.post(
        "/v1/models",
        headers=root,
        json={"provider": "test", "name": "x", "model_string": "test:x"},
    )
    assert r.status_code == 201
    r = await client.get("/v1/models", headers=alice)
    assert len(r.json()) == 1


async def test_rejected_callback_destination_is_not_retried(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination refused by outbound policy is permanent. Retrying it
    would re-resolve the same name callback_max_tries times, all failing, and
    delay the operator's alert by the whole backoff schedule."""
    from arq import Retry

    from sleeper_service.runtime.outbound import OutboundUrlError

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    r = await _submit(
        client, bob, risk_agent["agent"]["id"], callback_url="https://receiver.example/hook"
    )
    job_id = uuid.UUID(r.json()["id"])
    await runner.execute_job(job_id)

    real_client = httpx.AsyncClient  # bind before patching to avoid recursion
    attempts = 0

    async def rejecting_target(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise OutboundUrlError("callback URL hostname resolves to a non-public address")

    def unreachable_client(**kwargs):  # pragma: no cover
        raise AssertionError("a rejected destination must never be contacted")

    monkeypatch.setattr(callbacks, "validate_callback_target", rejecting_target)
    monkeypatch.setattr(callbacks.httpx, "AsyncClient", unreachable_client)

    # first try, well below callback_max_tries: still terminal, no Retry raised
    await deliver_callback({"job_try": 1}, str(job_id))
    assert attempts == 1

    r = await client.get(f"/v1/jobs/{job_id}/events", headers=bob)
    failures = [e for e in r.json() if e["type"] == "callback_failed"]
    assert len(failures) == 1
    assert "not retrying" in failures[0]["data"]["error"]

    # a transient failure at the same job_try still retries, so the change is
    # scoped to policy rejections rather than blanket give-up
    def failing_client(**kwargs) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(lambda req: httpx.Response(500)))

    monkeypatch.setattr(callbacks, "validate_callback_target", AsyncMock())
    monkeypatch.setattr(callbacks.httpx, "AsyncClient", failing_client)
    with pytest.raises(Retry):
        await deliver_callback({"job_try": 1}, str(job_id))
