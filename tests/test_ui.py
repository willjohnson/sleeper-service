"""Admin UI: session auth, page rendering, owner-gated actions."""

import re
import uuid

from httpx import AsyncClient

from sleeper_service.runtime import runner
from tests.conftest import auth


async def _login(client: AsyncClient, email: str, password: str = "password-123"):
    page = await client.get("/ui/login")
    token = re.search(r'name="_csrf_token" value="([^"]+)"', page.text).group(1)
    r = await client.post(
        "/ui/login",
        data={"email": email, "password": password, "_csrf_token": token},
        follow_redirects=False,
    )
    return r


def _csrf(html: str) -> str:
    return re.search(r'name="_csrf_token" value="([^"]+)"', html).group(1)


async def test_login_flow(client: AsyncClient, risk_agent: dict) -> None:
    # wrong password rejected
    r = await _login(client, "alice@example.com", "wrong")
    assert r.status_code == 401

    r = await _login(client, "alice@example.com")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui"

    # authenticated home redirects into the tenant dashboard
    r = await client.get("/ui", follow_redirects=False)
    assert r.status_code == 303
    assert "/ui/t/" in r.headers["location"]

    r = await client.get(r.headers["location"])
    assert r.status_code == 200
    assert "Dashboard" in r.text
    assert "Live agents" in r.text


async def test_unauthenticated_redirects_to_login(client: AsyncClient) -> None:
    r = await client.get("/ui", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"


async def test_agents_and_detail_pages(client: AsyncClient, risk_agent: dict) -> None:
    await _login(client, "bob@example.com")
    tenant_id = risk_agent["tenant"]["id"]
    agent_id = risk_agent["agent"]["id"]

    r = await client.get(f"/ui/t/{tenant_id}/agents")
    assert r.status_code == 200
    assert "risk-analyzer" in r.text

    r = await client.get(f"/ui/agents/{agent_id}")
    assert r.status_code == 200
    assert "Versions" in r.text
    assert "test:default" in r.text
    # editor sees no Promote button
    assert "Promote" not in r.text


async def test_promote_via_ui_owner_only(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/versions",
        headers=bob,
        json={"prompt": "v2", "model": "test/default"},
    )
    assert r.status_code == 201

    # editor's POST is a no-op
    await _login(client, "bob@example.com")
    page = await client.get(f"/ui/agents/{agent_id}")
    await client.post(
        f"/ui/agents/{agent_id}/promote/2", data={"_csrf_token": _csrf(page.text)}
    )
    r = await client.get(f"/v1/agents/{agent_id}", headers=bob)
    current = r.json()["current_version_id"]
    assert current == risk_agent["version"]["id"]

    # owner promotes; page shows the Promote button
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/agents/{agent_id}")
    assert "Promote" in page.text
    await client.post(
        f"/ui/agents/{agent_id}/promote/2", data={"_csrf_token": _csrf(page.text)}
    )
    r = await client.get(f"/v1/agents/{agent_id}", headers=bob)
    assert r.json()["current_version_id"] != current


async def test_job_page_and_outsider_blocked(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=bob, json={"context": {"prompt": "hi"}}
    )
    job_id = r.json()["id"]
    await runner.execute_job(uuid.UUID(job_id))

    await _login(client, "bob@example.com")
    r = await client.get(f"/ui/jobs/{job_id}")
    assert r.status_code == 200
    assert "Payload" in r.text
    assert "succeeded" in r.text

    # outsider bounced to home
    await _login(client, "dave@example.com")
    r = await client.get(f"/ui/jobs/{job_id}", follow_redirects=False)
    assert r.status_code == 303


async def test_ui_posts_require_csrf(client: AsyncClient, risk_agent: dict) -> None:
    await _login(client, "alice@example.com")
    r = await client.post(f"/ui/agents/{risk_agent['agent']['id']}/promote/1")
    assert r.status_code == 403


async def test_login_is_rate_limited(client: AsyncClient) -> None:
    page = await client.get("/ui/login")
    token = _csrf(page.text)
    email = f"rate-limit-{uuid.uuid4()}@example.com"
    for _ in range(10):
        r = await client.post(
            "/ui/login",
            data={
                "email": email,
                "password": "wrong",
                "_csrf_token": token,
            },
        )
        assert r.status_code == 401
    r = await client.post(
        "/ui/login",
        data={
            "email": email,
            "password": "wrong",
            "_csrf_token": token,
        },
    )
    assert r.status_code == 429
