"""Phase 0 done-criteria: tenant → team → agent via API; a viewer key can't edit."""

import uuid

from httpx import AsyncClient

from tests.conftest import Bootstrap, auth


async def test_tenant_creation_requires_superuser(client: AsyncClient, org: dict) -> None:
    alice = auth(org["users"]["alice"]["api_key"])
    r = await client.post("/v1/tenants", headers=alice, json={"name": "evil-corp"})
    assert r.status_code == 403


async def test_tenant_seeds_org_team(client: AsyncClient, bootstrap: Bootstrap) -> None:
    root = auth(bootstrap.superuser_key)
    r = await client.post("/v1/tenants", headers=root, json={"name": "acme"})
    teams = await client.get(f"/v1/tenants/{r.json()['id']}/teams", headers=root)
    assert [t["name"] for t in teams.json()] == ["org"]
    assert teams.json()[0]["is_org_team"] is True


async def test_editor_creates_agent_viewer_cannot(client: AsyncClient, org: dict) -> None:
    bob = auth(org["users"]["bob"]["api_key"])
    carol = auth(org["users"]["carol"]["api_key"])
    payload = {
        "team_id": org["team"]["id"],
        "name": "risk-analyzer",
        "description": "Assess business risk for events",
    }
    r = await client.post("/v1/agents", headers=carol, json=payload)
    assert r.status_code == 403  # the Phase 0 done-criterion

    r = await client.post("/v1/agents", headers=bob, json=payload)
    assert r.status_code == 201
    agent = r.json()

    # viewer can read but not edit
    r = await client.get(f"/v1/agents/{agent['id']}", headers=carol)
    assert r.status_code == 200
    r = await client.patch(f"/v1/agents/{agent['id']}", headers=carol, json={"description": "nope"})
    assert r.status_code == 403

    # editor edits; only owner deletes
    r = await client.patch(
        f"/v1/agents/{agent['id']}", headers=bob, json={"description": "updated"}
    )
    assert r.status_code == 200
    assert r.json()["description"] == "updated"
    r = await client.delete(f"/v1/agents/{agent['id']}", headers=bob)
    assert r.status_code == 403
    alice = auth(org["users"]["alice"]["api_key"])
    r = await client.delete(f"/v1/agents/{agent['id']}", headers=alice)
    assert r.status_code == 204


async def test_outsider_sees_nothing(client: AsyncClient, org: dict) -> None:
    bob = auth(org["users"]["bob"]["api_key"])
    dave = auth(org["users"]["dave"]["api_key"])

    r = await client.post(
        "/v1/agents",
        headers=bob,
        json={"team_id": org["team"]["id"], "name": "secret-agent"},
    )
    agent_id = r.json()["id"]

    r = await client.get("/v1/tenants", headers=dave)
    assert r.json() == []
    r = await client.get(f"/v1/agents/{agent_id}", headers=dave)
    assert r.status_code == 404
    r = await client.get("/v1/agents", headers=dave)
    assert r.json() == []
    r = await client.get(f"/v1/teams/{org['team']['id']}", headers=dave)
    assert r.status_code == 404


async def test_duplicate_agent_name_in_tenant_conflicts(client: AsyncClient, org: dict) -> None:
    bob = auth(org["users"]["bob"]["api_key"])
    payload = {"team_id": org["team"]["id"], "name": "dupe"}
    assert (await client.post("/v1/agents", headers=bob, json=payload)).status_code == 201
    assert (await client.post("/v1/agents", headers=bob, json=payload)).status_code == 409


async def test_last_owner_cannot_be_demoted_or_removed(client: AsyncClient, org: dict) -> None:
    alice_id = org["users"]["alice"]["id"]
    team_id = org["team"]["id"]
    alice = auth(org["users"]["alice"]["api_key"])

    r = await client.put(
        f"/v1/teams/{team_id}/members/{alice_id}", headers=alice, json={"role": "editor"}
    )
    assert r.status_code == 409
    r = await client.delete(f"/v1/teams/{team_id}/members/{alice_id}", headers=alice)
    assert r.status_code == 409


async def test_invoke_keys(client: AsyncClient, org: dict) -> None:
    alice = auth(org["users"]["alice"]["api_key"])
    carol = auth(org["users"]["carol"]["api_key"])
    team_id = org["team"]["id"]

    # only team owners issue invoke keys
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=carol,
        json={"scope": "team", "scope_id": team_id},
    )
    assert r.status_code == 403
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=alice,
        json={"scope": "team", "scope_id": team_id, "name": "n8n"},
    )
    assert r.status_code == 201
    invoke_key = r.json()["api_key"]
    assert invoke_key.startswith("ss_invoke_")

    # invoke keys are locked out of every management endpoint
    for method, url, body in [
        ("get", "/v1/tenants", None),
        ("get", "/v1/agents", None),
        ("post", "/v1/agents", {"team_id": team_id, "name": "sneaky"}),
        ("get", f"/v1/teams/{team_id}/members", None),
    ]:
        r = await client.request(method, url, headers=auth(invoke_key), json=body)
        assert r.status_code == 403, f"{method} {url} let an invoke key through"

    # owner revokes it
    keys = (await client.get("/v1/api-keys", headers=alice)).json()
    assert len(keys) == 1
    r = await client.delete(f"/v1/api-keys/{keys[0]['id']}", headers=alice)
    assert r.status_code == 204
    r = await client.get("/v1/agents", headers=auth(invoke_key))
    assert r.status_code == 401


async def test_unrelated_team_owner_cannot_issue_key_for_other_team(
    client: AsyncClient, bootstrap: Bootstrap, org: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    r = await client.post(
        "/v1/users",
        headers=root,
        json={"email": "eve@example.com", "password": "password-123"},
    )
    eve_user = r.json()
    r = await client.post(
        f"/v1/tenants/{org['tenant']['id']}/teams",
        headers=root,
        json={"name": "other", "owner_user_id": eve_user["id"]},
    )
    assert r.status_code == 201
    eve = auth(eve_user["api_key"])
    r = await client.post(
        "/v1/api-keys/invoke",
        headers=eve,
        json={"scope": "team", "scope_id": org["team"]["id"]},
    )
    assert r.status_code in (403, 404)


async def test_nonexistent_resources_404(client: AsyncClient, org: dict) -> None:
    alice = auth(org["users"]["alice"]["api_key"])
    missing = uuid.uuid4()
    assert (await client.get(f"/v1/agents/{missing}", headers=alice)).status_code == 404
    assert (await client.get(f"/v1/teams/{missing}", headers=alice)).status_code == 404
    assert (await client.get(f"/v1/tenants/{missing}", headers=alice)).status_code == 404


async def test_provider_cred_scopes(client: AsyncClient, risk_agent: dict) -> None:
    """Team/agent creds: owner-managed, and resolution walks agent → team → tenant."""
    from sleeper_service.db.session import get_sessionmaker
    from sleeper_service.runtime.providers import resolve_api_key

    alice = auth(risk_agent["users"]["alice"]["api_key"])
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]
    team_id = risk_agent["team"]["id"]
    agent_id = risk_agent["agent"]["id"]

    # editors cannot manage creds at any scope
    for path in (
        f"/v1/teams/{team_id}/provider-creds/openai",
        f"/v1/agents/{agent_id}/provider-creds/openai",
    ):
        r = await client.put(path, headers=bob, json={"api_key": "sk-nope"})
        assert r.status_code == 403
    # alice owns the risk team but is not a tenant admin
    r = await client.put(
        f"/v1/tenants/{tenant_id}/provider-creds/openai", headers=alice, json={"api_key": "sk-t"}
    )
    assert r.status_code == 403

    # team owner sets team- and agent-scoped creds
    r = await client.put(
        f"/v1/teams/{team_id}/provider-creds/openai", headers=alice, json={"api_key": "sk-team"}
    )
    assert r.status_code == 200 and r.json()["scope"] == "team"
    r = await client.put(
        f"/v1/agents/{agent_id}/provider-creds/openai", headers=alice, json={"api_key": "sk-agent"}
    )
    assert r.status_code == 200 and r.json()["scope"] == "agent"
    assert len((await client.get(f"/v1/teams/{team_id}/provider-creds", headers=alice)).json()) == 1

    # narrowest scope wins; deleting it falls back outward
    async with get_sessionmaker()() as db:
        from sleeper_service.db.models import Agent

        agent = await db.get(Agent, uuid.UUID(agent_id))
        assert await resolve_api_key(db, agent, "openai") == "sk-agent"
        assert await resolve_api_key(db, agent, "anthropic") is None
    r = await client.delete(f"/v1/agents/{agent_id}/provider-creds/openai", headers=alice)
    assert r.status_code == 204
    async with get_sessionmaker()() as db:
        agent = await db.get(Agent, uuid.UUID(agent_id))
        assert await resolve_api_key(db, agent, "openai") == "sk-team"
