import hashlib
import hmac
import json
import re
import socket
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from pydantic_ai import ModelRetry
from sqlalchemy import select

from sleeper_service.crypto import encrypt
from sleeper_service.db.models import Agent, AgentVersion, DataStore, Job, McpServer, Team, Tenant
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime.delegation import _ancestry
from sleeper_service.runtime.links import fetch_links
from sleeper_service.runtime.outbound import OutboundUrlError, validate_callback_target
from sleeper_service.runtime.toolsets import (
    GrantError,
    _lookup,
    _StoreGrant,
    build_mcp_toolsets,
)
from tests.conftest import auth


def test_store_grant_resolve_path_traversal():
    store = DataStore(
        id=uuid.uuid4(), name="test_store", type="local", config={"base_path": "/tmp"}
    )

    grant_empty = _StoreGrant(store, prefix="", mode="ro")
    assert grant_empty.resolve("valid/path.txt") == "valid/path.txt"
    assert grant_empty.resolve("") == "."

    with pytest.raises(ModelRetry, match="escapes the granted prefix"):
        grant_empty.resolve("../../etc/passwd")
    with pytest.raises(ModelRetry, match="escapes the granted prefix"):
        grant_empty.resolve("../secret")

    grant_reports = _StoreGrant(store, prefix="reports", mode="ro")
    assert grant_reports.resolve("2026/jan.txt") == "reports/2026/jan.txt"
    with pytest.raises(ModelRetry, match="escapes the granted prefix"):
        grant_reports.resolve("../other/secret.txt")
    with pytest.raises(ModelRetry, match="escapes the granted prefix"):
        grant_reports.resolve("../../secret.txt")


def test_store_grant_resolve_is_cwd_independent(monkeypatch):
    monkeypatch.chdir("/")
    store = DataStore(
        id=uuid.uuid4(), name="test_store", type="local", config={"base_path": "/tmp"}
    )
    grant = _StoreGrant(store, prefix="", mode="ro")
    for path in ["../../etc/passwd", "..", "../secret", "a/../../secret"]:
        with pytest.raises(ModelRetry):
            grant.resolve(path)
    assert grant.resolve("valid/path.txt") == "valid/path.txt"


@pytest.mark.asyncio
async def test_ancestry_circular_reference_guard():
    job1_id = uuid.uuid4()
    job2_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    job1 = Job(id=job1_id, agent_id=agent_id, parent_job_id=job2_id)
    job2 = Job(id=job2_id, agent_id=agent_id, parent_job_id=job1_id)

    db = AsyncMock()

    def get_job(model, jid):
        return {job1_id: job1, job2_id: job2}.get(jid)

    db.get.side_effect = get_job
    depth, agent_ids = await _ancestry(db, job1)
    assert depth == 1
    assert agent_id in agent_ids


@pytest.mark.asyncio
async def test_ssrf_redirect_blocked():
    import httpx

    async def mock_get(url, follow_redirects=False):
        if url == "https://allowed.example.com/redirect":
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )
        return httpx.Response(200, text="meta-data")

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        blocks = await fetch_links(
            ["https://allowed.example.com/redirect"], {"link_allowlist": ["allowed.example.com"]}
        )
        assert len(blocks) == 1
        assert "host not in tenant allowlist" in blocks[0]


@pytest.mark.asyncio
async def test_fetch_links_denies_all_without_allowlist():
    import httpx

    async def mock_get(url, follow_redirects=False):  # pragma: no cover
        raise AssertionError("no request should be made without an allowlist")

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        for settings in (None, {}):
            blocks = await fetch_links(["https://anything.example.com/"], settings)
            assert len(blocks) == 1
            assert "host not in tenant allowlist" in blocks[0]


@pytest.mark.asyncio
async def test_callback_target_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
        ],
    )
    with pytest.raises(OutboundUrlError, match="non-public"):
        await validate_callback_target("https://callback.example/hook")
    with pytest.raises(OutboundUrlError, match="non-public"):
        await validate_callback_target("http://169.254.169.254/latest/meta-data")


@pytest.mark.asyncio
async def test_integration_uuid_lookup_is_tenant_qualified():
    async with get_sessionmaker()() as db:
        tenant_a = Tenant(name="lookup-a")
        tenant_b = Tenant(name="lookup-b")
        db.add_all([tenant_a, tenant_b])
        await db.flush()
        server = McpServer(
            tenant_id=tenant_b.id,
            name="private-server",
            endpoint="https://mcp.example",
            transport="streamable_http",
        )
        db.add(server)
        await db.commit()

        assert await _lookup(db, McpServer, tenant_a.id, str(server.id)) is None
        assert await _lookup(db, McpServer, tenant_b.id, str(server.id)) == server


@pytest.mark.asyncio
async def test_user_context_requires_per_server_signature(monkeypatch):
    from sleeper_service.runtime import toolsets

    captured = {}

    class FakeToolset:
        def filtered(self, predicate):
            return self

    def fake_toolset(*args, **kwargs):
        captured.update(kwargs)
        return FakeToolset()

    monkeypatch.setattr(toolsets, "MCPToolset", fake_toolset)
    async with get_sessionmaker()() as db:
        tenant = Tenant(name="context-tenant")
        db.add(tenant)
        await db.flush()
        server = McpServer(
            tenant_id=tenant.id,
            name="signed-server",
            endpoint="https://mcp.example",
            transport="streamable_http",
            credentials_enc=encrypt(json.dumps({"headers": {"Authorization": "Bearer x"}})),
        )
        db.add(server)
        await db.commit()

        with pytest.raises(GrantError, match="user_ctx_signing_secret"):
            await build_mcp_toolsets(
                db,
                tenant.id,
                [{"server": str(server.id)}],
                {"claimed_user": "admin"},
                {"type": "invoke_key", "key_id": "trusted"},
            )

        server.credentials_enc = encrypt(json.dumps({"user_ctx_signing_secret": "mcp-secret"}))
        await db.commit()
        await build_mcp_toolsets(
            db,
            tenant.id,
            [{"server": str(server.id)}],
            {"claimed_user": "admin"},
            {"type": "invoke_key", "key_id": "trusted"},
        )

    headers = captured["headers"]
    payload = headers["X-Sleeper-User-Ctx"]
    timestamp = headers["X-Sleeper-User-Ctx-Timestamp"]
    expected = hmac.new(
        b"mcp-secret", f"{timestamp}.{payload}".encode(), hashlib.sha256
    ).hexdigest()
    assert headers["X-Sleeper-User-Ctx-Signature"] == f"v1={expected}"
    assert json.loads(payload)["principal"]["key_id"] == "trusted"


@pytest.mark.asyncio
async def test_secretless_server_fails_closed_after_credentialed_grant(monkeypatch):
    # creds must not leak across grant iterations: a server without any
    # credentials must still fail closed on user_ctx, even when an earlier
    # grant in the same version resolved a server that has a signing secret.
    from sleeper_service.runtime import toolsets

    captured = []

    class FakeToolset:
        def filtered(self, predicate):
            return self

    def fake_toolset(*args, **kwargs):
        captured.append(kwargs)
        return FakeToolset()

    monkeypatch.setattr(toolsets, "MCPToolset", fake_toolset)
    async with get_sessionmaker()() as db:
        tenant = Tenant(name="creds-leak-tenant")
        db.add(tenant)
        await db.flush()
        db.add_all(
            [
                McpServer(
                    tenant_id=tenant.id,
                    name="signed",
                    endpoint="https://a.example",
                    transport="streamable_http",
                    credentials_enc=encrypt(json.dumps({"user_ctx_signing_secret": "s1"})),
                ),
                McpServer(
                    tenant_id=tenant.id,
                    name="bare",
                    endpoint="https://b.example",
                    transport="streamable_http",
                ),
            ]
        )
        await db.commit()

        with pytest.raises(GrantError, match="user_ctx_signing_secret"):
            await build_mcp_toolsets(
                db,
                tenant.id,
                [{"server": "signed"}, {"server": "bare"}],
                {"claimed_user": "admin"},
                {"type": "user", "user_id": "u1"},
            )

    forwarded = [c for c in captured if (c.get("headers") or {}).get("X-Sleeper-User-Ctx")]
    assert len(forwarded) == 1, "user_ctx must not reach the secretless server"


@pytest.mark.asyncio
async def test_tenant_admin_cannot_register_stdio_mcp(client, org, bootstrap):
    async with get_sessionmaker()() as db:
        org_team = await db.scalar(
            select(Team).where(
                Team.tenant_id == uuid.UUID(org["tenant"]["id"]), Team.is_org_team.is_(True)
            )
        )
    root = auth(bootstrap.superuser_key)
    alice_id = org["users"]["alice"]["id"]
    r = await client.put(
        f"/v1/teams/{org_team.id}/members/{alice_id}",
        headers=root,
        json={"role": "owner"},
    )
    assert r.status_code == 200

    r = await client.post(
        f"/v1/tenants/{org['tenant']['id']}/mcp-servers",
        headers=auth(org["users"]["alice"]["api_key"]),
        json={"name": "host-command", "transport": "stdio", "endpoint": "sh -c id"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_tenant_admin_cannot_register_local_data_store(client, org, bootstrap):
    async with get_sessionmaker()() as db:
        org_team = await db.scalar(
            select(Team).where(
                Team.tenant_id == uuid.UUID(org["tenant"]["id"]),
                Team.is_org_team.is_(True),
            )
        )
    root = auth(bootstrap.superuser_key)
    alice = auth(org["users"]["alice"]["api_key"])
    r = await client.put(
        f"/v1/teams/{org_team.id}/members/{org['users']['alice']['id']}",
        headers=root,
        json={"role": "owner"},
    )
    assert r.status_code == 200

    # a tenant admin cannot point a data store at the service container's fs
    r = await client.post(
        f"/v1/tenants/{org['tenant']['id']}/data-stores",
        headers=alice,
        json={"name": "host-fs", "type": "local", "config": {"base_path": "/"}},
    )
    assert r.status_code == 403

    # an instance superuser can (operators own the host fs)
    r = await client.post(
        f"/v1/tenants/{org['tenant']['id']}/data-stores",
        headers=root,
        json={"name": "host-fs", "type": "local", "config": {"base_path": "/tmp"}},
    )
    assert r.status_code == 201

    # tenant admins retain the other backends
    r = await client.post(
        f"/v1/tenants/{org['tenant']['id']}/data-stores",
        headers=alice,
        json={"name": "bucket", "type": "s3", "config": {"bucket": "b"}},
    )
    assert r.status_code == 201


@pytest.mark.asyncio
async def test_job_submission_rejects_private_callback(client, risk_agent):
    r = await client.post(
        f"/v1/agents/{risk_agent['agent']['id']}/jobs",
        headers=auth(risk_agent["users"]["bob"]["api_key"]),
        json={
            "context": {"prompt": "test"},
            "callback_url": "http://169.254.169.254/latest/meta-data",
        },
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_job_tree_hides_unauthorized_descendants(client, risk_agent):
    async with get_sessionmaker()() as db:
        hidden_team = Team(
            tenant_id=uuid.UUID(risk_agent["tenant"]["id"]), name="hidden-team"
        )
        db.add(hidden_team)
        await db.flush()
        hidden_agent = Agent(
            tenant_id=uuid.UUID(risk_agent["tenant"]["id"]),
            team_id=hidden_team.id,
            name="hidden-agent",
        )
        db.add(hidden_agent)
        await db.flush()
        hidden_version = AgentVersion(
            agent_id=hidden_agent.id,
            version_no=1,
            prompt="hidden",
            max_iterations=1,
            timeout_s=1,
        )
        db.add(hidden_version)
        await db.flush()
        parent = Job(
            agent_id=uuid.UUID(risk_agent["agent"]["id"]),
            agent_version_id=uuid.UUID(risk_agent["version"]["id"]),
            payload={"prompt": "visible"},
        )
        db.add(parent)
        await db.flush()
        child = Job(
            agent_id=hidden_agent.id,
            agent_version_id=hidden_version.id,
            parent_job_id=parent.id,
            payload={"prompt": "secret child payload"},
            output={"secret": "hidden output"},
        )
        db.add(child)
        await db.commit()
        parent_id = parent.id

    r = await client.get(
        f"/v1/jobs/{parent_id}/tree",
        headers=auth(risk_agent["users"]["bob"]["api_key"]),
    )
    assert r.status_code == 200
    assert r.json()["children"] == []


@pytest.mark.asyncio
async def test_dashboard_filters_unauthorized_teams(client, risk_agent):
    async with get_sessionmaker()() as db:
        hidden_team = Team(
            tenant_id=uuid.UUID(risk_agent["tenant"]["id"]), name="dashboard-hidden"
        )
        db.add(hidden_team)
        await db.flush()
        hidden_agent = Agent(
            tenant_id=uuid.UUID(risk_agent["tenant"]["id"]),
            team_id=hidden_team.id,
            name="dashboard-secret-agent",
        )
        db.add(hidden_agent)
        await db.flush()
        hidden_version = AgentVersion(
            agent_id=hidden_agent.id,
            version_no=1,
            prompt="hidden",
            max_iterations=1,
            timeout_s=1,
        )
        db.add(hidden_version)
        await db.flush()
        hidden_job = Job(
            agent_id=hidden_agent.id,
            agent_version_id=hidden_version.id,
            payload={"prompt": "hidden"},
        )
        db.add(hidden_job)
        await db.commit()

    login = await client.get("/ui/login")
    token = re.search(r'name="_csrf_token" value="([^"]+)"', login.text).group(1)
    r = await client.post(
        "/ui/login",
        data={
            "email": "bob@example.com",
            "password": "password-123",
            "_csrf_token": token,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    dashboard = await client.get(f"/ui/t/{risk_agent['tenant']['id']}")
    assert "dashboard-secret-agent" not in dashboard.text
    assert str(hidden_job.id) not in dashboard.text
    assert '<div class="num">1</div><div class="label">Total agents</div>' in dashboard.text
