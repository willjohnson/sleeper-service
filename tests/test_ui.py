"""Admin UI: session auth, page rendering, owner-gated actions."""

import re
import uuid

from httpx import AsyncClient

from sleeper_service.runtime import runner
from tests.conftest import Bootstrap, auth


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
    await client.post(f"/ui/agents/{agent_id}/promote/2", data={"_csrf_token": _csrf(page.text)})
    r = await client.get(f"/v1/agents/{agent_id}", headers=bob)
    current = r.json()["current_version_id"]
    assert current == risk_agent["version"]["id"]

    # owner promotes; page shows the Promote button
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/agents/{agent_id}")
    assert "Promote" in page.text
    await client.post(f"/ui/agents/{agent_id}/promote/2", data={"_csrf_token": _csrf(page.text)})
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


async def test_csrf_token_rotates_on_login(client: AsyncClient, risk_agent: dict) -> None:
    """The pre-auth token must not survive into the authenticated session.

    Whoever established the pre-auth session knows that token; if login kept
    it, they could forge state-changing requests once the victim signed in.
    """
    page = await client.get("/ui/login")
    pre_auth = _csrf(page.text)

    r = await client.post(
        "/ui/login",
        data={"email": "alice@example.com", "password": "password-123", "_csrf_token": pre_auth},
        follow_redirects=False,
    )
    assert r.status_code == 303

    agent_id = risk_agent["agent"]["id"]
    dashboard = await client.get(f"/ui/agents/{agent_id}")
    post_auth = _csrf(dashboard.text)
    assert post_auth != pre_auth, "login must mint a new CSRF token"

    # the old token is dead: a request carrying it is refused
    r = await client.post(f"/ui/agents/{agent_id}/promote/1", data={"_csrf_token": pre_auth})
    assert r.status_code == 403
    # ...and the new one still works
    r = await client.post(
        f"/ui/agents/{agent_id}/promote/1",
        data={"_csrf_token": post_auth},
        follow_redirects=False,
    )
    assert r.status_code == 303


async def test_csrf_token_rotates_on_logout_then_login(client: AsyncClient) -> None:
    """Logout clears the session, so the next login starts from a fresh token
    rather than resurrecting the previous session's."""
    await _login(client, "alice@example.com")
    signed_in = _csrf((await client.get("/ui/login")).text)
    await client.post("/ui/logout", data={"_csrf_token": signed_in})

    await _login(client, "alice@example.com")
    after = _csrf((await client.get("/ui/login")).text)
    assert after != signed_in


def _request(peer: str = "10.0.0.1", forwarded: str | None = None):
    """A bare Starlette request with the given peer address and XFF header."""
    from starlette.requests import Request

    headers = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {"type": "http", "client": (peer, 1234), "headers": headers, "method": "GET", "path": "/"}
    )


def test_client_ip_ignores_forwarded_header_by_default(monkeypatch):
    """Default deployment is direct, so X-Forwarded-For is attacker-supplied
    and must not be honoured — otherwise varying it per request sidesteps the
    login limiter entirely, which is worse than keying on the proxy."""
    from sleeper_service.config import get_settings
    from sleeper_service.ui.routes import client_ip

    monkeypatch.setattr(get_settings(), "trusted_proxy_hops", 0)
    assert client_ip(_request(peer="10.0.0.1", forwarded="1.2.3.4")) == "10.0.0.1"
    assert client_ip(_request(peer="10.0.0.1")) == "10.0.0.1"


def test_client_ip_reads_through_trusted_hops(monkeypatch):
    from sleeper_service.config import get_settings
    from sleeper_service.ui.routes import client_ip

    settings = get_settings()

    # one proxy: it appended the address it saw, so the client is rightmost
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    assert client_ip(_request(forwarded="203.0.113.7")) == "203.0.113.7"

    # two proxies: the rightmost entry is the inner proxy, the client is next
    monkeypatch.setattr(settings, "trusted_proxy_hops", 2)
    assert client_ip(_request(forwarded="203.0.113.7, 172.16.0.9")) == "203.0.113.7"

    # a client prepending its own entries cannot move the selection: with one
    # trusted hop the real address is still the one the proxy appended
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    assert client_ip(_request(forwarded="9.9.9.9, 8.8.8.8, 203.0.113.7")) == "203.0.113.7"


def test_client_ip_falls_back_when_header_is_unusable(monkeypatch):
    from sleeper_service.config import get_settings
    from sleeper_service.ui.routes import client_ip

    monkeypatch.setattr(get_settings(), "trusted_proxy_hops", 2)
    # header absent, malformed, or shorter than the configured hop count
    assert client_ip(_request(peer="10.0.0.1")) == "10.0.0.1"
    assert client_ip(_request(peer="10.0.0.1", forwarded="not-an-ip")) == "10.0.0.1"
    assert client_ip(_request(peer="10.0.0.1", forwarded="  ,  ")) == "10.0.0.1"
    # one entry but two hops configured: take the leftmost rather than wrap
    assert client_ip(_request(peer="10.0.0.1", forwarded="203.0.113.7")) == "203.0.113.7"


async def test_login_rate_limit_is_per_client_not_per_proxy(
    client: AsyncClient, monkeypatch
) -> None:
    """Behind a proxy the peer address is constant, so without this the limit
    is effectively per-email: one attacker exhausts it and the real user is
    locked out from anywhere."""
    from sleeper_service.config import get_settings

    monkeypatch.setattr(get_settings(), "trusted_proxy_hops", 1)
    page = await client.get("/ui/login")
    token = _csrf(page.text)
    email = f"proxy-limit-{uuid.uuid4()}@example.com"

    attacker = {"X-Forwarded-For": "203.0.113.7"}
    for _ in range(10):
        r = await client.post(
            "/ui/login",
            data={"email": email, "password": "wrong", "_csrf_token": token},
            headers=attacker,
        )
        assert r.status_code == 401
    r = await client.post(
        "/ui/login",
        data={"email": email, "password": "wrong", "_csrf_token": token},
        headers=attacker,
    )
    assert r.status_code == 429, "the attacker's own address should be limited"

    # a different client address for the same email has its own budget
    r = await client.post(
        "/ui/login",
        data={"email": email, "password": "wrong", "_csrf_token": token},
        headers={"X-Forwarded-For": "198.51.100.4"},
    )
    assert r.status_code == 401, "one address must not lock the account for others"


# --- Creating agents and versions from the UI ---


async def _agents_page(client: AsyncClient, tenant_id: str) -> str:
    r = await client.get(f"/ui/t/{tenant_id}/agents")
    assert r.status_code == 200
    return r.text


async def test_create_agent_makes_a_runnable_agent(
    client: AsyncClient, org: dict, seeded_models: None
) -> None:
    await _login(client, "alice@example.com")
    listing = await _agents_page(client, org["tenant"]["id"])
    assert f"/ui/t/{org['tenant']['id']}/agents/new" in listing

    page = await client.get(f"/ui/t/{org['tenant']['id']}/agents/new")
    assert page.status_code == 200
    assert "First version" in page.text

    r = await client.post(
        f"/ui/t/{org['tenant']['id']}/agents",
        data={
            "_csrf_token": _csrf(page.text),
            "team_id": org["team"]["id"],
            "name": "credit-memo",
            "description": "Draft credit memos",
            "spending_limit": "12.50",
            "model": "test:default",
            "prompt": "You are a credit analyst.",
            "max_iterations": "7",
            "timeout_s": "120",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    agent_id = r.headers["location"].rsplit("/", 1)[-1]

    alice = auth(org["users"]["alice"]["api_key"])
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=alice)).json()
    assert agent["name"] == "credit-memo"
    assert agent["spending_limit"] == "12.5000"
    # The first version exists and was auto-promoted, so the agent can run.
    assert agent["current_version_id"] is not None
    versions = (await client.get(f"/v1/agents/{agent_id}/versions", headers=alice)).json()
    assert len(versions) == 1
    assert versions[0]["version_no"] == 1
    assert versions[0]["prompt"] == "You are a credit analyst."
    assert versions[0]["max_iterations"] == 7
    assert versions[0]["timeout_s"] == 120
    assert versions[0]["id"] == agent["current_version_id"]


async def test_create_agent_hidden_and_refused_for_viewers(
    client: AsyncClient, org: dict, seeded_models: None
) -> None:
    await _login(client, "carol@example.com")  # viewer
    listing = await _agents_page(client, org["tenant"]["id"])
    assert "/agents/new" not in listing

    # The page itself is not reachable...
    r = await client.get(f"/ui/t/{org['tenant']['id']}/agents/new", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].endswith("/agents")

    # ...and neither is the endpoint behind it.
    r = await client.post(
        f"/ui/t/{org['tenant']['id']}/agents",
        data={
            "_csrf_token": _csrf(listing),
            "team_id": org["team"]["id"],
            "name": "sneaky",
            "model": "test:default",
            "prompt": "hello",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    alice = auth(org["users"]["alice"]["api_key"])
    assert (await client.get("/v1/agents", headers=alice)).json() == []


async def test_governed_options_are_owner_only(
    client: AsyncClient, org: dict, seeded_models: None
) -> None:
    base = {
        "team_id": org["team"]["id"],
        "name": "learner",
        "model": "test:default",
        "prompt": "hello",
        "learning": "1",
    }
    await _login(client, "bob@example.com")  # editor
    page = await client.get(f"/ui/t/{org['tenant']['id']}/agents/new")
    r = await client.post(
        f"/ui/t/{org['tenant']['id']}/agents",
        data={"_csrf_token": _csrf(page.text), **base},
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "owner-managed" in r.text

    await _login(client, "alice@example.com")  # owner
    page = await client.get(f"/ui/t/{org['tenant']['id']}/agents/new")
    r = await client.post(
        f"/ui/t/{org['tenant']['id']}/agents",
        data={"_csrf_token": _csrf(page.text), **base},
        follow_redirects=False,
    )
    assert r.status_code == 303
    agent_id = r.headers["location"].rsplit("/", 1)[-1]
    alice = auth(org["users"]["alice"]["api_key"])
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=alice)).json()
    assert agent["options"] == {"learning": True}


async def test_create_agent_errors_keep_the_typed_prompt(
    client: AsyncClient, risk_agent: dict
) -> None:
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/t/{risk_agent['tenant']['id']}/agents/new")
    r = await client.post(
        f"/ui/t/{risk_agent['tenant']['id']}/agents",
        data={
            "_csrf_token": _csrf(page.text),
            "team_id": risk_agent["team"]["id"],
            "name": "risk-analyzer",  # already taken
            "model": "test:default",
            "prompt": "A prompt that took a while to write.",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "already exists" in r.text
    assert "A prompt that took a while to write." in r.text


async def test_create_agent_validates_prompt_and_model(
    client: AsyncClient, org: dict, seeded_models: None
) -> None:
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/t/{org['tenant']['id']}/agents/new")
    common = {
        "_csrf_token": _csrf(page.text),
        "team_id": org["team"]["id"],
        "name": "nope",
    }
    url = f"/ui/t/{org['tenant']['id']}/agents"

    r = await client.post(url, data={**common, "model": "test:default", "prompt": "   "})
    assert r.status_code == 400 and "needs a prompt" in r.text

    r = await client.post(url, data={**common, "model": "nonesuch:v1", "prompt": "hi"})
    assert r.status_code == 400 and "Unknown model" in r.text

    r = await client.post(
        url, data={**common, "model": "test:default", "prompt": "hi", "max_iterations": "999"}
    )
    assert r.status_code == 400 and "between 1 and 100" in r.text


async def test_create_version_from_agent_page(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "bob@example.com")  # editor
    detail = await client.get(f"/ui/agents/{agent_id}")
    assert f"/ui/agents/{agent_id}/versions/new" in detail.text

    page = await client.get(f"/ui/agents/{agent_id}/versions/new")
    assert page.status_code == 200
    assert "Saves as <strong>v2</strong>" in page.text
    # Prefilled from the current version so iterating is an edit, not a retype.
    textarea = page.text.split('id="nv-prompt"')[1].split("</textarea>")[0]
    assert "Assess business risk for the event in the payload." in textarea

    r = await client.post(
        f"/ui/agents/{agent_id}/versions",
        data={
            "_csrf_token": _csrf(page.text),
            "model": "anthropic:claude-sonnet-5",
            "prompt": "Assess business risk, and cite the payload fields you used.",
            "max_iterations": "12",
            "timeout_s": "90",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/ui/agents/{agent_id}"

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    versions = (await client.get(f"/v1/agents/{agent_id}/versions", headers=bob)).json()
    assert [v["version_no"] for v in versions] == [1, 2]
    assert versions[1]["max_iterations"] == 12
    # A later version does not auto-promote — that stays an owner action.
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=bob)).json()
    assert agent["current_version_id"] == versions[0]["id"]


async def test_create_version_refused_for_viewers(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "carol@example.com")  # viewer
    page = await client.get(f"/ui/agents/{agent_id}")
    assert "/versions/new" not in page.text

    r = await client.get(f"/ui/agents/{agent_id}/versions/new", follow_redirects=False)
    assert r.status_code == 303

    r = await client.post(
        f"/ui/agents/{agent_id}/versions",
        data={"_csrf_token": _csrf(page.text), "model": "test:default", "prompt": "hi"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    versions = (await client.get(f"/v1/agents/{agent_id}/versions", headers=bob)).json()
    assert len(versions) == 1


async def test_edit_agent_settings(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "bob@example.com")  # editor
    detail = await client.get(f"/ui/agents/{agent_id}")
    assert f"/ui/agents/{agent_id}/settings" in detail.text

    page = await client.get(f"/ui/agents/{agent_id}/settings")
    assert page.status_code == 200
    assert 'value="risk-analyzer"' in page.text  # prefilled from the agent

    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={
            "_csrf_token": _csrf(page.text),
            "name": "risk-analyzer-renamed",
            "description": "Now with a better description",
            "spending_limit": "25",
            "delegation": "team",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=bob)).json()
    assert agent["name"] == "risk-analyzer-renamed"
    assert agent["description"] == "Now with a better description"
    assert agent["spending_limit"] == "25.0000"
    assert agent["options"] == {"delegation": "team"}
    # Editing settings must not create a version.
    versions = (await client.get(f"/v1/agents/{agent_id}/versions", headers=bob)).json()
    assert len(versions) == 1


async def test_edit_clears_spending_limit_and_rejects_bad_input(
    client: AsyncClient, risk_agent: dict
) -> None:
    agent_id = risk_agent["agent"]["id"]
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    await client.patch(f"/v1/agents/{agent_id}", headers=alice, json={"spending_limit": "9"})

    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/agents/{agent_id}/settings")
    token = _csrf(page.text)

    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={"_csrf_token": token, "name": "risk-analyzer", "spending_limit": "-3"},
    )
    assert r.status_code == 400 and "greater than zero" in r.text

    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={"_csrf_token": token, "name": "", "spending_limit": "1"},
    )
    assert r.status_code == 400 and "Name is required" in r.text

    # Blank clears the limit.
    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={"_csrf_token": token, "name": "risk-analyzer", "spending_limit": "  "},
        follow_redirects=False,
    )
    assert r.status_code == 303
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=alice)).json()
    assert agent["spending_limit"] is None


async def test_edit_keeps_owner_options_when_an_editor_saves(
    client: AsyncClient, risk_agent: dict
) -> None:
    """An editor changing a description must not read as flipping memory off."""
    agent_id = risk_agent["agent"]["id"]
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    r = await client.patch(
        f"/v1/agents/{agent_id}", headers=alice, json={"options": {"memory": True}}
    )
    assert r.status_code == 200

    await _login(client, "bob@example.com")  # editor
    page = await client.get(f"/ui/agents/{agent_id}/settings")
    # The checkbox is disabled for editors, so the template round-trips the
    # owner's setting in a hidden field. Without it the save would read as
    # flipping memory off and be refused.
    assert '<input type="hidden" name="memory" value="1">' in page.text
    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={
            "_csrf_token": _csrf(page.text),
            "name": "risk-analyzer",
            "description": "Edited by an editor",
            "spending_limit": "",
            "memory": "1",  # what the browser sends from the hidden field
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=alice)).json()
    assert agent["description"] == "Edited by an editor"
    assert agent["options"] == {"memory": True}


async def test_editor_cannot_flip_governed_options(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "bob@example.com")  # editor
    page = await client.get(f"/ui/agents/{agent_id}/settings")
    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={
            "_csrf_token": _csrf(page.text),
            "name": "risk-analyzer",
            "spending_limit": "",
            "learning": "1",
        },
    )
    assert r.status_code == 400 and "owner-managed" in r.text


async def test_edit_hidden_and_refused_for_viewers(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "carol@example.com")  # viewer
    page = await client.get(f"/ui/agents/{agent_id}")
    assert "/settings" not in page.text

    r = await client.get(f"/ui/agents/{agent_id}/settings", follow_redirects=False)
    assert r.status_code == 303

    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={"_csrf_token": _csrf(page.text), "name": "hijacked", "spending_limit": ""},
        follow_redirects=False,
    )
    assert r.status_code == 303
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=bob)).json()
    assert agent["name"] == "risk-analyzer"


async def test_settings_error_keeps_the_typed_input(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/agents/{agent_id}/settings")
    r = await client.post(
        f"/ui/agents/{agent_id}/settings",
        data={
            "_csrf_token": _csrf(page.text),
            "name": "",  # invalid
            "description": "A description worth keeping",
            "spending_limit": "",
        },
    )
    assert r.status_code == 400
    assert "Name is required" in r.text
    # Re-rendered as the edit page, not the detail page, with input intact.
    assert f'action="/ui/agents/{agent_id}/settings"' in r.text
    assert "A description worth keeping" in r.text


async def test_form_pages_are_closed_for_archived_agents(
    client: AsyncClient, risk_agent: dict
) -> None:
    agent_id = risk_agent["agent"]["id"]
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    assert (await client.post(f"/v1/agents/{agent_id}/archive", headers=alice)).status_code == 200

    await _login(client, "alice@example.com")
    for path in (f"/ui/agents/{agent_id}/settings", f"/ui/agents/{agent_id}/versions/new"):
        r = await client.get(path, follow_redirects=False)
        assert r.status_code == 303, path
        assert r.headers["location"] == f"/ui/agents/{agent_id}"


# --- Archiving ---


async def test_archive_hides_agent_and_refuses_new_work(
    client: AsyncClient, risk_agent: dict
) -> None:
    agent_id = risk_agent["agent"]["id"]
    tenant_id = risk_agent["tenant"]["id"]
    alice = auth(risk_agent["users"]["alice"]["api_key"])

    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/agents/{agent_id}")
    r = await client.post(
        f"/ui/agents/{agent_id}/archive",
        data={"_csrf_token": _csrf(page.text)},
        follow_redirects=False,
    )
    assert r.status_code == 303

    # Gone from the active table, listed under Archived instead.
    page = await _agents_page(client, tenant_id)
    assert "Archived (1)" in page
    active = page.split("Archived (1)")[0]
    assert "risk-analyzer" not in active

    # Refuses new work through the API...
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=alice, json={"context": {"prompt": "check this"}}
    )
    assert r.status_code == 409
    assert "archived" in r.json()["detail"]

    # ...and drops out of API listings unless asked for.
    listed = (await client.get("/v1/agents", headers=alice)).json()
    assert [a["id"] for a in listed] == []
    listed = (await client.get("/v1/agents?include_archived=true", headers=alice)).json()
    assert [a["id"] for a in listed] == [agent_id]

    # History survives.
    versions = (await client.get(f"/v1/agents/{agent_id}/versions", headers=alice)).json()
    assert len(versions) == 1


async def test_restore_brings_the_agent_back(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    assert (await client.post(f"/v1/agents/{agent_id}/archive", headers=alice)).status_code == 200

    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/agents/{agent_id}")
    assert "Archived" in page.text
    # An archived agent offers no way to give it more work.
    assert "New version" not in page.text

    r = await client.post(
        f"/ui/agents/{agent_id}/restore",
        data={"_csrf_token": _csrf(page.text)},
        follow_redirects=False,
    )
    assert r.status_code == 303

    page = await client.get(f"/ui/agents/{agent_id}")
    assert "New version" in page.text
    r = await client.post(
        f"/v1/agents/{agent_id}/jobs", headers=alice, json={"context": {"prompt": "check this"}}
    )
    assert r.status_code in (201, 202)


async def test_archive_is_owner_only(client: AsyncClient, risk_agent: dict) -> None:
    agent_id = risk_agent["agent"]["id"]
    await _login(client, "bob@example.com")  # editor
    page = await client.get(f"/ui/agents/{agent_id}")
    assert "Archive agent" not in page.text

    r = await client.post(
        f"/ui/agents/{agent_id}/archive",
        data={"_csrf_token": _csrf(page.text)},
        follow_redirects=False,
    )
    assert r.status_code == 303
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent = (await client.get(f"/v1/agents/{agent_id}", headers=bob)).json()
    assert agent["archived_at"] is None


# --- Creating teams ---

# A tenant's org-wide team is created without an owner (see create_tenant), so
# in these fixtures the instance superuser is the tenant admin for "acme".
ROOT = ("root@example.com", "root-password")


async def test_create_team_via_ui(client: AsyncClient, org: dict, bootstrap: Bootstrap) -> None:
    tenant_id = org["tenant"]["id"]
    await _login(client, *ROOT)
    listing = await _agents_page(client, tenant_id)
    assert f"/ui/t/{tenant_id}/teams/new" in listing

    page = await client.get(f"/ui/t/{tenant_id}/teams/new")
    assert page.status_code == 200

    r = await client.post(
        f"/ui/t/{tenant_id}/teams",
        data={"_csrf_token": _csrf(page.text), "name": "compliance"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/ui/t/{tenant_id}/agents"

    # Verified as the superuser: a team's creator is its only member, so the
    # other users in the tenant cannot see it yet.
    root = auth(bootstrap.superuser_key)
    teams = (await client.get(f"/v1/tenants/{tenant_id}/teams", headers=root)).json()
    team = next(t for t in teams if t["name"] == "compliance")
    members = (await client.get(f"/v1/teams/{team['id']}/members", headers=root)).json()
    assert [m["role"] for m in members] == ["owner"]
    # ...and it shows up straight away on the agents page.
    assert "compliance" in await _agents_page(client, tenant_id)


async def test_create_team_can_name_another_tenant_user_as_owner(
    client: AsyncClient, org: dict, bootstrap: Bootstrap
) -> None:
    tenant_id = org["tenant"]["id"]
    await _login(client, *ROOT)
    page = await client.get(f"/ui/t/{tenant_id}/teams/new")
    # Only people already in the tenant are offered; dave is in no team.
    assert "bob@example.com" in page.text
    assert "dave@example.com" not in page.text

    r = await client.post(
        f"/ui/t/{tenant_id}/teams",
        data={
            "_csrf_token": _csrf(page.text),
            "name": "platform",
            "owner_user_id": org["users"]["bob"]["id"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    root = auth(bootstrap.superuser_key)
    teams = (await client.get(f"/v1/tenants/{tenant_id}/teams", headers=root)).json()
    team = next(t for t in teams if t["name"] == "platform")
    members = (await client.get(f"/v1/teams/{team['id']}/members", headers=root)).json()
    assert [(str(m["user_id"]), m["role"]) for m in members] == [
        (org["users"]["bob"]["id"], "owner")
    ]


async def test_create_team_rejects_outsider_as_owner(client: AsyncClient, org: dict) -> None:
    tenant_id = org["tenant"]["id"]
    await _login(client, *ROOT)
    page = await client.get(f"/ui/t/{tenant_id}/teams/new")
    r = await client.post(
        f"/ui/t/{tenant_id}/teams",
        data={
            "_csrf_token": _csrf(page.text),
            "name": "smuggled",
            "owner_user_id": org["users"]["dave"]["id"],  # not in this tenant
        },
    )
    assert r.status_code == 400
    assert "Pick an owner from this tenant" in r.text


async def test_create_team_validates_name(client: AsyncClient, org: dict) -> None:
    tenant_id = org["tenant"]["id"]
    await _login(client, *ROOT)
    page = await client.get(f"/ui/t/{tenant_id}/teams/new")
    token = _csrf(page.text)

    r = await client.post(f"/ui/t/{tenant_id}/teams", data={"_csrf_token": token, "name": "  "})
    assert r.status_code == 400 and "Name is required" in r.text

    r = await client.post(f"/ui/t/{tenant_id}/teams", data={"_csrf_token": token, "name": "risk"})
    assert r.status_code == 400 and "already exists" in r.text


async def test_create_team_is_tenant_admin_only(client: AsyncClient, org: dict) -> None:
    """Owning a team is not enough — it takes the org-wide team's owner."""
    tenant_id = org["tenant"]["id"]
    await _login(client, "alice@example.com")  # owner of "risk", not of the org team
    listing = await _agents_page(client, tenant_id)
    assert "/teams/new" not in listing

    r = await client.get(f"/ui/t/{tenant_id}/teams/new", follow_redirects=False)
    assert r.status_code == 303

    r = await client.post(
        f"/ui/t/{tenant_id}/teams",
        data={"_csrf_token": _csrf(listing), "name": "sneaky"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    teams = (
        await client.get(
            f"/v1/tenants/{tenant_id}/teams", headers=auth(org["users"]["alice"]["api_key"])
        )
    ).json()
    assert "sneaky" not in [t["name"] for t in teams]


# --- Team membership ---


async def test_team_page_lists_members(client: AsyncClient, org: dict) -> None:
    team_id = org["team"]["id"]
    await _login(client, "carol@example.com")  # viewer
    listing = await _agents_page(client, org["tenant"]["id"])
    assert f"/ui/teams/{team_id}" in listing

    page = await client.get(f"/ui/teams/{team_id}")
    assert page.status_code == 200
    for email in ("alice@example.com", "bob@example.com", "carol@example.com"):
        assert email in page.text
    # A viewer sees the roster but is offered no controls.
    assert "Add a member" not in page.text
    assert "/remove" not in page.text


async def test_owner_adds_member_by_email(client: AsyncClient, org: dict) -> None:
    team_id = org["team"]["id"]
    alice = auth(org["users"]["alice"]["api_key"])
    await _login(client, "alice@example.com")  # owner
    page = await client.get(f"/ui/teams/{team_id}")
    # Tenant colleagues are suggested; dave is in no team here, so he is not.
    assert "Add a member" in page.text
    assert "dave@example.com" not in page.text

    r = await client.post(
        f"/ui/teams/{team_id}/members",
        data={
            "_csrf_token": _csrf(page.text),
            "email": "Dave@Example.com",  # matched case-insensitively
            "role": "editor",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    members = (await client.get(f"/v1/teams/{team_id}/members", headers=alice)).json()
    by_id = {str(m["user_id"]): m["role"] for m in members}
    assert by_id[org["users"]["dave"]["id"]] == "editor"


async def test_adding_an_unknown_email_is_refused(client: AsyncClient, org: dict) -> None:
    team_id = org["team"]["id"]
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/teams/{team_id}")
    r = await client.post(
        f"/ui/teams/{team_id}/members",
        data={"_csrf_token": _csrf(page.text), "email": "nobody@example.com", "role": "viewer"},
    )
    assert r.status_code == 400
    assert "No user with the email" in r.text


async def test_owner_changes_and_removes_members(client: AsyncClient, org: dict) -> None:
    team_id = org["team"]["id"]
    alice = auth(org["users"]["alice"]["api_key"])
    bob_id = org["users"]["bob"]["id"]
    await _login(client, "alice@example.com")
    page = await client.get(f"/ui/teams/{team_id}")
    token = _csrf(page.text)

    r = await client.post(
        f"/ui/teams/{team_id}/members/{bob_id}/role",
        data={"_csrf_token": token, "role": "owner"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    members = (await client.get(f"/v1/teams/{team_id}/members", headers=alice)).json()
    assert {str(m["user_id"]): m["role"] for m in members}[bob_id] == "owner"

    r = await client.post(
        f"/ui/teams/{team_id}/members/{org['users']['carol']['id']}/remove",
        data={"_csrf_token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    members = (await client.get(f"/v1/teams/{team_id}/members", headers=alice)).json()
    assert org["users"]["carol"]["id"] not in [str(m["user_id"]) for m in members]


async def test_the_last_owner_cannot_be_demoted_or_removed(client: AsyncClient, org: dict) -> None:
    """Mirrors _forbid_removing_last_owner: the UI must not offer it either."""
    team_id = org["team"]["id"]
    alice_id = org["users"]["alice"]["id"]
    await _login(client, "alice@example.com")  # the only owner
    page = await client.get(f"/ui/teams/{team_id}")
    assert "last owner" in page.text
    assert f"/members/{alice_id}/remove" not in page.text
    assert f"/members/{alice_id}/role" not in page.text
    token = _csrf(page.text)

    for path in (f"/members/{alice_id}/role", f"/members/{alice_id}/remove"):
        r = await client.post(
            f"/ui/teams/{team_id}{path}", data={"_csrf_token": token, "role": "viewer"}
        )
        assert r.status_code == 400, path
        assert "at least one owner" in r.text

    alice = auth(org["users"]["alice"]["api_key"])
    members = (await client.get(f"/v1/teams/{team_id}/members", headers=alice)).json()
    assert {str(m["user_id"]): m["role"] for m in members}[alice_id] == "owner"


async def test_member_management_is_team_owner_only(client: AsyncClient, org: dict) -> None:
    team_id = org["team"]["id"]
    await _login(client, "bob@example.com")  # editor
    page = await client.get(f"/ui/teams/{team_id}")
    assert "Add a member" not in page.text

    r = await client.post(
        f"/ui/teams/{team_id}/members",
        data={"_csrf_token": _csrf(page.text), "email": "dave@example.com", "role": "owner"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/ui/teams/{team_id}"

    alice = auth(org["users"]["alice"]["api_key"])
    members = (await client.get(f"/v1/teams/{team_id}/members", headers=alice)).json()
    assert org["users"]["dave"]["id"] not in [str(m["user_id"]) for m in members]


async def test_outsider_cannot_see_a_team(client: AsyncClient, org: dict) -> None:
    await _login(client, "dave@example.com")  # no membership anywhere
    r = await client.get(f"/ui/teams/{org['team']['id']}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui"
