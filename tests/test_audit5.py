"""Regression tests for security audit 5 (docs/SECURITY_AUDIT_REPORT_5.md).

Covers the three findings fixed in the audit pass:

1. MCP HTTP endpoints are server-initiated outbound destinations and must
   clear the same address policy as callbacks and fetched links — at
   registration (syntax/policy) and at toolset-build time (fresh resolution).
2. File uploads are rejected on their rolled size before the body is read
   into memory, so an oversized upload cannot exhaust it.
3. Invoke keys scoped below the tenant do not get tenant-wide file access.

And the three audit-5 design tensions Will decided to close (2026-08-19):

eval jobs are subject to spending limits and spend rollups; request bodies
are size-capped; eval matches_regex checks run bounded by a timeout.
"""

import socket
import time
import uuid
from decimal import Decimal

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select

from sleeper_service.api.v1.files import MAX_FILE_SIZE, upload_file
from sleeper_service.auth.principal import UserPrincipal
from sleeper_service.config import get_settings
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    EvalCase,
    EvalRun,
    Job,
    McpServer,
    Team,
    Tenant,
    User,
)
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import runner, spending
from sleeper_service.runtime.evals import run_check, validate_checks
from sleeper_service.runtime.toolsets import GrantError, build_mcp_toolsets
from tests.conftest import auth


def _resolves_to(address: str):
    """Pin DNS so outbound validation is exercised without real lookups."""
    return lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]


def _forbid_resolution(*args, **kwargs):  # pragma: no cover
    raise AssertionError("no DNS resolution should happen when private hosts are allowed")


# --- Finding 1: MCP HTTP endpoints are unvalidated outbound destinations ---


async def test_mcp_http_registration_rejects_private_endpoints(
    client: AsyncClient, org: dict, bootstrap
) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]

    for i, endpoint in enumerate(
        (
            "http://169.254.169.254/mcp",  # cloud metadata, as a literal
            "http://localhost:9000/mcp",  # loopback by name
            "https://intranet.acme.internal/mcp",  # non-public suffix
        )
    ):
        r = await client.post(
            f"/v1/tenants/{tenant_id}/mcp-servers",
            headers=root,
            json={"name": f"private-{i}", "endpoint": endpoint, "transport": "streamable_http"},
        )
        assert r.status_code == 422, f"{endpoint} was accepted: {r.text}"

    # a public endpoint still registers
    r = await client.post(
        f"/v1/tenants/{tenant_id}/mcp-servers",
        headers=root,
        json={
            "name": "public-server",
            "endpoint": "https://mcp.example.com/mcp",
            "transport": "streamable_http",
        },
    )
    assert r.status_code == 201, r.text

    # stdio endpoints are command lines (superuser-gated), not URLs: untouched
    r = await client.post(
        f"/v1/tenants/{tenant_id}/mcp-servers",
        headers=root,
        json={"name": "stdio-server", "endpoint": "python stub.py", "transport": "stdio"},
    )
    assert r.status_code == 201, r.text


async def test_mcp_toolset_build_rejects_privately_resolving_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registration checked the syntax; DNS can move before a job runs. The
    connect-time check must resolve, exactly like callback delivery."""
    from sleeper_service.runtime import toolsets

    monkeypatch.setattr(socket, "getaddrinfo", _resolves_to("169.254.169.254"))

    class FakeToolset:
        def filtered(self, predicate):
            return self

    monkeypatch.setattr(toolsets, "MCPToolset", lambda *a, **k: FakeToolset())

    async with get_sessionmaker()() as db:
        tenant = Tenant(name="mcp-rebind-tenant")
        db.add(tenant)
        await db.flush()
        db.add(
            McpServer(
                tenant_id=tenant.id,
                name="rebinding",
                endpoint="https://rebind.example/mcp",
                transport="streamable_http",
            )
        )
        await db.commit()

        with pytest.raises(GrantError, match="endpoint"):
            await build_mcp_toolsets(db, tenant.id, [{"server": "rebinding"}], None, None)


async def test_mcp_private_endpoints_allowed_when_operator_opts_in(
    client: AsyncClient, org: dict, bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MCP_ALLOW_PRIVATE_HOSTS is the operator opt-in for MCP servers that
    share a network with the worker (the compose mcp-* sidecar shape). With it
    set, syntax is still enforced but no address check or resolution runs."""
    from sleeper_service.runtime import toolsets

    monkeypatch.setattr(get_settings(), "mcp_allow_private_hosts", True)
    monkeypatch.setattr(socket, "getaddrinfo", _forbid_resolution)

    class FakeToolset:
        def filtered(self, predicate):
            return self

    monkeypatch.setattr(toolsets, "MCPToolset", lambda *a, **k: FakeToolset())

    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    r = await client.post(
        f"/v1/tenants/{tenant_id}/mcp-servers",
        headers=root,
        json={
            "name": "sidecar",
            "endpoint": "http://mcp-sidecar:8000/mcp",
            "transport": "streamable_http",
        },
    )
    assert r.status_code == 201, r.text

    # non-http syntax is still refused with the flag on
    r = await client.post(
        f"/v1/tenants/{tenant_id}/mcp-servers",
        headers=root,
        json={"name": "gopher", "endpoint": "gopher://mcp-sidecar/mcp", "transport": "sse"},
    )
    assert r.status_code == 422, r.text

    async with get_sessionmaker()() as db:
        built = await build_mcp_toolsets(
            db, uuid.UUID(tenant_id), [{"server": "sidecar"}], None, None
        )
    assert built  # no GrantError, no connection attempt


async def test_mcp_private_flag_keeps_url_syntax_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator opt-in skips only the address policy: credentials-in-URL
    and malformed ports are refused exactly as on every other outbound path,
    instead of being stored and failing opaquely at job runtime."""
    from sleeper_service.runtime.outbound import OutboundUrlError, validate_mcp_url

    monkeypatch.setattr(get_settings(), "mcp_allow_private_hosts", True)

    with pytest.raises(OutboundUrlError, match="credentials"):
        validate_mcp_url("http://user:pass@mcp-sidecar:8000/mcp")
    with pytest.raises(OutboundUrlError, match="port"):
        validate_mcp_url("http://mcp-sidecar:99999/mcp")
    validate_mcp_url("http://mcp-sidecar:8000/mcp")  # in-policy sidecar still fine


# --- Finding 2: oversized uploads must be rejected before they are read ---


async def test_oversized_upload_rejected_before_reading(bootstrap) -> None:
    class ExplodingUpload:
        """An upload whose rolled size already exceeds the cap: reading it
        into memory is exactly what the size guard exists to prevent."""

        filename = "big.bin"
        content_type = "application/octet-stream"
        size = MAX_FILE_SIZE + 1

        async def read(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("oversized upload content must not be read into memory")

    async with get_sessionmaker()() as db:
        user = await db.get(User, bootstrap.superuser_id)
        principal = UserPrincipal(user=user, roles={})
        with pytest.raises(HTTPException) as exc_info:
            await upload_file(
                tenant_id=bootstrap.tenant_id, file=ExplodingUpload(), db=db, principal=principal
            )
        assert exc_info.value.status_code == 413


# --- Finding 3: invoke-key scope vs tenant-wide file access ---


async def test_invoke_key_scope_gates_file_access(
    client: AsyncClient, org: dict, risk_agent: dict, bootstrap
) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(org["users"]["alice"]["api_key"])
    bob = auth(org["users"]["bob"]["api_key"])
    tenant_id = org["tenant"]["id"]
    agent_id = risk_agent["agent"]["id"]

    # a tenant-covering key and an agent-scoped key
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=root,
        json={"scope": "tenant", "scope_id": tenant_id, "name": "tenant-wide"},
    )
    assert r.status_code == 201, r.text
    tenant_key = auth(r.json()["api_key"])
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=alice,
        json={"scope": "agent", "scope_id": agent_id, "name": "one-agent"},
    )
    assert r.status_code == 201, r.text
    agent_key = auth(r.json()["api_key"])

    r = await client.post(
        f"/v1/files?tenant_id={tenant_id}",
        headers=bob,
        files={"file": ("notes.txt", b"tenant data", "text/plain")},
    )
    assert r.status_code == 201, r.text
    file_id = r.json()["id"]

    # tenant-covering key: within the documented file boundary
    r = await client.get(f"/v1/files/{file_id}/content", headers=tenant_key)
    assert r.status_code == 200 and r.content == b"tenant data"

    # agent-scoped key: no file surface at all — neither read nor upload
    r = await client.get(f"/v1/files/{file_id}/content", headers=agent_key)
    assert r.status_code == 404, "agent-scoped invoke key read a tenant file"
    r = await client.get(f"/v1/files/{file_id}", headers=agent_key)
    assert r.status_code == 404
    r = await client.post(
        f"/v1/files?tenant_id={tenant_id}",
        headers=agent_key,
        files={"file": ("x.txt", b"x", "text/plain")},
    )
    assert r.status_code == 404, "agent-scoped invoke key uploaded a tenant file"


async def test_narrow_invoke_key_cannot_reference_files_in_jobs(
    client: AsyncClient, org: dict, risk_agent: dict
) -> None:
    """The file boundary by another door: the runner inlines context.files
    into the prompt and the submitter reads the content back through the job
    output, so job submission enforces the same tenant-key-only rule."""
    alice = auth(org["users"]["alice"]["api_key"])
    bob = auth(org["users"]["bob"]["api_key"])
    tenant_id = org["tenant"]["id"]
    agent_id = risk_agent["agent"]["id"]

    r = await client.post(
        "/v1/api-keys/invoke",
        headers=alice,
        json={"scope": "agent", "scope_id": agent_id, "name": "job-file-probe"},
    )
    assert r.status_code == 201, r.text
    agent_key = auth(r.json()["api_key"])

    r = await client.post(
        f"/v1/files?tenant_id={tenant_id}",
        headers=bob,
        files={"file": ("secret.txt", b"tenant secret", "text/plain")},
    )
    assert r.status_code == 201, r.text
    file_id = r.json()["id"]

    r = await client.post(
        f"/v1/agents/{agent_id}/jobs",
        headers=agent_key,
        json={"context": {"prompt": "read it", "files": [file_id]}},
    )
    assert r.status_code == 403, "agent-scoped invoke key attached a tenant file to a job"

    # without files the same key still submits within its scope
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs",
        headers=agent_key,
        json={"context": {"prompt": "no files"}},
    )
    assert r.status_code == 202, r.text


# --- Post-audit follow-up: eval jobs subject to spending limits and rollups ---


async def test_eval_spend_counts_in_month_spend() -> None:
    """Eval jobs are part of the agent's monthly spend, not invisible to it."""
    async with get_sessionmaker()() as db:
        tenant = Tenant(name="eval-spend-tenant")
        db.add(tenant)
        await db.flush()
        team = Team(tenant_id=tenant.id, name="org")
        db.add(team)
        await db.flush()
        agent = Agent(tenant_id=tenant.id, team_id=team.id, name="eval-agent")
        db.add(agent)
        await db.flush()
        version = AgentVersion(agent_id=agent.id, version_no=1, prompt="p")
        db.add(version)
        await db.flush()
        db.add(
            Job(
                agent_id=agent.id,
                agent_version_id=version.id,
                payload={},
                status="succeeded",
                cost=Decimal("3"),
            )
        )
        db.add(
            Job(
                agent_id=agent.id,
                agent_version_id=version.id,
                payload={},
                status="succeeded",
                cost=Decimal("2"),
                is_eval=True,
            )
        )
        await db.commit()

        assert await spending.month_spend(db, agent.id) == Decimal("5")


async def test_eval_job_refused_at_exhausted_budget(client: AsyncClient, risk_agent: dict) -> None:
    """The runner's budget pre-flight applies to eval jobs like any other."""
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    version_id = risk_agent["version"]["id"]

    r = await client.patch(f"/v1/agents/{agent_id}", headers=bob, json={"spending_limit": "5"})
    assert r.status_code == 200

    async with get_sessionmaker()() as db:
        db.add(
            Job(
                agent_id=uuid.UUID(agent_id),
                agent_version_id=uuid.UUID(version_id),
                payload={},
                status="succeeded",
                cost=Decimal("5"),
            )
        )
        eval_job = Job(
            agent_id=uuid.UUID(agent_id),
            agent_version_id=uuid.UUID(version_id),
            payload={"prompt": "assess"},
            is_eval=True,
        )
        db.add(eval_job)
        await db.commit()
        eval_job_id = eval_job.id

    await runner.execute_job(eval_job_id)

    async with get_sessionmaker()() as db:
        job = await db.get(Job, eval_job_id)
    assert job.status == "budget_exceeded"
    assert "reached limit" in job.error


async def test_eval_job_mid_run_budget(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single eval job accruing cost past the limit dies between model calls."""
    from pydantic_ai.messages import ModelResponse, TextPart
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    version_id = risk_agent["version"]["id"]
    r = await client.patch(f"/v1/agents/{agent_id}", headers=bob, json={"spending_limit": "0.05"})
    assert r.status_code == 200

    def chatty_model(*_args) -> FunctionModel:
        async def respond(messages: list, info: AgentInfo) -> ModelResponse:
            return ModelResponse(parts=[TextPart("still thinking...")])

        return FunctionModel(respond)

    monkeypatch.setattr(runner, "build_model", chatty_model)
    monkeypatch.setattr(
        runner, "_calc_cost", lambda usage, model_name: Decimal("0.03") * usage.requests
    )

    async with get_sessionmaker()() as db:
        eval_job = Job(
            agent_id=uuid.UUID(agent_id),
            agent_version_id=uuid.UUID(version_id),
            payload={"prompt": "assess"},
            is_eval=True,
        )
        db.add(eval_job)
        await db.commit()
        eval_job_id = eval_job.id

    await runner.execute_job(eval_job_id)

    async with get_sessionmaker()() as db:
        job = await db.get(Job, eval_job_id)
    assert job.status == "budget_exceeded"
    assert "mid-run" in job.error


async def test_start_eval_run_refused_at_exhausted_budget(
    client: AsyncClient, risk_agent: dict
) -> None:
    """The API refuses a manual eval run before creating it, like job submission."""
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    r = await client.post(
        f"/v1/agents/{agent_id}/eval-cases",
        headers=bob,
        json={
            "name": "case-1",
            "input": {"prompt": "assess"},
            "checks": [{"path": "risk_level", "op": "equals", "value": "low"}],
        },
    )
    assert r.status_code == 201

    r = await client.patch(f"/v1/agents/{agent_id}", headers=bob, json={"spending_limit": "0"})
    assert r.status_code == 200

    r = await client.post(f"/v1/agents/{agent_id}/eval-runs", headers=bob, json={})
    assert r.status_code == 409
    assert "monthly spend" in r.json()["detail"]


async def test_run_eval_refused_at_exhausted_budget(client: AsyncClient, risk_agent: dict) -> None:
    """run_eval refuses at the top — not only in the API route — because the
    memory eval gate enqueues runs without passing through it, and a queued
    run can outlive its pre-flight. Completing instead at 0% would fire a
    spurious regression alert and then become the baseline that masks a real
    one."""
    from sleeper_service.runtime.evals import run_eval

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    version_id = risk_agent["version"]["id"]

    r = await client.patch(f"/v1/agents/{agent_id}", headers=bob, json={"spending_limit": "0"})
    assert r.status_code == 200

    async with get_sessionmaker()() as db:
        db.add(
            EvalCase(
                agent_id=uuid.UUID(agent_id),
                name="never-runs",
                input={"prompt": "assess"},
                checks=[{"path": "risk_level", "op": "equals", "value": "low"}],
            )
        )
        run = EvalRun(agent_id=uuid.UUID(agent_id), agent_version_id=uuid.UUID(version_id))
        db.add(run)
        await db.commit()
        run_id = run.id

    await run_eval(run_id)

    async with get_sessionmaker()() as db:
        run = await db.get(EvalRun, run_id)
    assert run.status == "budget_exceeded"
    assert run.pass_rate is None  # unevaluated, not 0%
    assert run.finished_at is not None

    # no case job was created for the refused run
    async with get_sessionmaker()() as db:
        eval_jobs = list(
            await db.scalars(
                select(Job).where(Job.agent_id == uuid.UUID(agent_id), Job.is_eval.is_(True))
            )
        )
    assert eval_jobs == []


# --- Post-audit follow-up: JSON request body cap ---


async def test_oversized_json_body_rejected(client: AsyncClient, risk_agent: dict) -> None:
    """JSON endpoints buffer the whole body to parse it, so the body is capped."""
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    cap = get_settings().request_body_max_bytes

    r = await client.post(
        f"/v1/agents/{agent_id}/jobs",
        headers=bob,
        json={"context": {"prompt": "x" * (cap + 1)}},
    )
    assert r.status_code == 413
    assert "exceeds" in r.json()["detail"]

    # an in-range body still reaches the endpoint
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs",
        headers=bob,
        json={"context": {"prompt": "in range"}},
    )
    assert r.status_code == 202


async def test_json_body_limit_counts_streamed_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chunked requests carry no Content-Length, so the cap is enforced on the
    bytes as they stream in, not only on the header."""
    from sleeper_service.main import BodyLimitMiddleware

    monkeypatch.setattr(get_settings(), "request_body_max_bytes", 10)

    async def run_over(body_chunks: list[bytes]) -> tuple[bool, list[dict]]:
        messages = [
            {"type": "http.request", "body": chunk, "more_body": i < len(body_chunks) - 1}
            for i, chunk in enumerate(body_chunks)
        ]
        stream = iter(messages)

        async def receive():
            return next(stream)

        app_completed = False

        async def inner_app(scope, receive, send):
            nonlocal app_completed
            while True:
                message = await receive()
                if message["type"] == "http.request" and not message.get("more_body"):
                    break
            app_completed = True

        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "headers": [(b"content-type", b"application/json")]}
        await BodyLimitMiddleware(inner_app)(scope, receive, send)
        return app_completed, sent

    # over the cap across two chunks: rejected, app never finishes the body
    app_completed, sent = await run_over([b"a" * 6, b"a" * 6])
    assert not app_completed
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413

    # under the cap: the body reaches the app intact
    app_completed, sent = await run_over([b"a" * 5, b"a" * 5])
    assert app_completed
    assert not sent  # the inner app sent no response of its own


async def test_body_limit_applies_regardless_of_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FastAPI buffers the whole body before it inspects the Content-Type or
    resolves auth, so a JSON-only cap is bypassed by relabelling the body
    text/plain — the cap engages on every request except multipart, which
    Starlette streams and the files route caps on the rolled size."""
    from sleeper_service.main import BodyLimitMiddleware

    monkeypatch.setattr(get_settings(), "request_body_max_bytes", 10)

    async def run_with(content_type: bytes, body: bytes) -> tuple[bool, list[dict]]:
        reached_app = False

        async def inner_app(scope, receive, send):
            nonlocal reached_app
            reached_app = True
            while True:
                message = await receive()
                if message["type"] == "http.request" and not message.get("more_body"):
                    break

        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        messages = iter([{"type": "http.request", "body": body, "more_body": False}])

        async def receive():
            return next(messages)

        scope = {
            "type": "http",
            "headers": [
                (b"content-type", content_type),
                (b"content-length", str(len(body)).encode()),
            ],
        }
        await BodyLimitMiddleware(inner_app)(scope, receive, send)
        return reached_app, sent

    # an oversized body declared text/plain: rejected on the header, app never runs
    reached_app, sent = await run_with(b"text/plain", b"a" * 11)
    assert not reached_app
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413

    # ...and with no recognizable JSON type at all
    reached_app, sent = await run_with(b"application/hal+json", b"a" * 11)
    assert not reached_app
    assert sent[0]["status"] == 413

    # multipart is the one exemption
    reached_app, sent = await run_with(b"multipart/form-data; boundary=x", b"a" * 11)
    assert reached_app
    assert not sent


# --- Post-audit follow-up: bounded matches_regex eval checks ---


def test_matches_regex_invalid_pattern_rejected_at_creation() -> None:
    error = validate_checks([{"op": "matches_regex", "path": "x", "value": "(unclosed"}])
    assert error is not None
    assert "regex" in error
    assert validate_checks([{"op": "matches_regex", "path": "x", "value": "^hi"}]) is None


def test_matches_regex_bounded_and_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An editor-supplied pattern that backtracks must not run unbounded, and
    a check that could not complete fails rather than passes."""
    from sleeper_service.runtime import evals as evals_mod

    monkeypatch.setattr(evals_mod, "REGEX_CHECK_TIMEOUT_S", 0.25)
    started = time.monotonic()
    ok, detail = run_check(
        {"op": "matches_regex", "path": "text", "value": "(a+)+b"},
        {"text": "a" * 4000},
        None,
    )
    elapsed = time.monotonic() - started

    assert ok is False
    assert "timed out" in detail
    assert elapsed < 3.0, f"the timeout did not bound the check ({elapsed:.1f}s)"


def test_matches_regex_invalid_pattern_fails_the_check() -> None:
    """A stored pattern that predates creation-time validation fails the check
    with the reason, instead of crashing the eval run."""
    ok, detail = run_check(
        {"op": "matches_regex", "path": "x", "value": "(unclosed"}, {"x": "y"}, None
    )
    assert ok is False
    assert "invalid regex" in detail


async def test_eval_case_rejects_invalid_regex(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    r = await client.post(
        f"/v1/agents/{agent_id}/eval-cases",
        headers=bob,
        json={
            "name": "bad-regex",
            "input": {"prompt": "assess"},
            "checks": [{"op": "matches_regex", "path": "risk_level", "value": "(unclosed"}],
        },
    )
    assert r.status_code == 422
