"""Unified human-work inbox and agent escalation."""

import re
import uuid

import pytest
from httpx import AsyncClient
from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from sleeper_service.db.models import WorkItem
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import memory, runner
from sleeper_service.runtime import work_items as work_items_runtime
from tests.conftest import auth


def _escalating_model(*_args) -> FunctionModel:
    def respond(messages: list, info: AgentInfo) -> ModelResponse:
        seen = [
            part.tool_name
            for message in messages
            for part in getattr(message, "parts", [])
            if isinstance(part, ToolCallPart)
        ]
        if "escalate_to_human" not in seen:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        tool_name="escalate_to_human",
                        args={
                            "summary": "Invoice needs billing review",
                            "reason": "The amount is 18% above the prior quarter.",
                            "severity": "high",
                            "requested_action": "Review and decide whether to send it.",
                        },
                    )
                ]
            )
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name="final_result",
                    args={"risk_level": "high", "factors": ["invoice"], "summary": "Escalated"},
                )
            ]
        )

    return FunctionModel(respond)


async def test_agent_escalation_creates_notifies_and_resolves_work_item(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    dave = auth(risk_agent["users"]["dave"]["api_key"])
    agent_id = risk_agent["agent"]["id"]
    tenant_id = risk_agent["tenant"]["id"]

    # Escalation is opt-in but is not an owner-only governance switch: the
    # editor who designs the agent's workflow may enable it.
    r = await client.patch(
        f"/v1/agents/{agent_id}", headers=bob, json={"options": {"human_escalation": True}}
    )
    assert r.status_code == 200

    alerts: list[tuple] = []

    async def fake_notify(agent_uuid, event_type, title, body, **kwargs):
        alerts.append((agent_uuid, event_type, title, body, kwargs))

    monkeypatch.setattr(runner, "build_model", _escalating_model)
    monkeypatch.setattr(work_items_runtime.notify, "notify", fake_notify)

    r = await client.post(
        f"/v1/agents/{agent_id}/jobs",
        headers=bob,
        json={"context": {"prompt": "Review this invoice"}},
    )
    job_id = r.json()["id"]
    await runner.execute_job(uuid.UUID(job_id))

    job = (await client.get(f"/v1/jobs/{job_id}", headers=bob)).json()
    assert job["status"] == "escalated"
    assert job["output"]["result"]["summary"] == "Escalated"
    work_item_id = job["output"]["work_item_ids"][0]

    assert len(alerts) == 1
    assert alerts[0][1] == "human_attention"
    assert alerts[0][4]["dedup_key"] == f"work-item:{work_item_id}"

    items = (await client.get(f"/v1/tenants/{tenant_id}/work-items", headers=carol)).json()
    assert [item["id"] for item in items] == [work_item_id]
    assert items[0]["kind"] == "human_escalation"
    assert items[0]["details"]["severity"] == "high"

    # No team relationship hides the tenant; a viewer can see but not resolve.
    assert (
        await client.get(f"/v1/tenants/{tenant_id}/work-items", headers=dave)
    ).status_code == 404
    r = await client.post(
        f"/v1/work-items/{work_item_id}/resolve",
        headers=carol,
        json={"resolution": "resolved", "response": "Send after correcting the amount."},
    )
    assert r.status_code == 403

    # Editors are the normal business-work resolvers; owners can resolve too.
    r = await client.post(
        f"/v1/work-items/{work_item_id}/resolve",
        headers=bob,
        json={"resolution": "resolved", "response": "Send after correcting the amount."},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    assert r.json()["response"] == {"text": "Send after correcting the amount."}
    assert (
        await client.post(
            f"/v1/work-items/{work_item_id}/resolve",
            headers=alice,
            json={"resolution": "resolved"},
        )
    ).status_code == 409

    events = (await client.get(f"/v1/jobs/{job_id}/events", headers=bob)).json()
    assert "human_escalated" in [event["type"] for event in events]
    assert "human_work_resolved" in [event["type"] for event in events]


async def test_memory_approval_uses_the_same_inbox(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice = auth(risk_agent["users"]["alice"]["api_key"])
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    agent_id = uuid.UUID(risk_agent["agent"]["id"])
    tenant_id = risk_agent["tenant"]["id"]

    alerts: list[tuple] = []

    async def fake_notify(*args, **kwargs):
        alerts.append((args, kwargs))

    monkeypatch.setattr(work_items_runtime.notify, "notify", fake_notify)
    await memory.write_memory(
        agent_id,
        "# Notes\nCross-check unusual invoice amounts.",
        None,
        pending=True,
    )

    items = (await client.get(f"/v1/tenants/{tenant_id}/work-items", headers=bob)).json()
    assert len(items) == 1
    item = items[0]
    assert item["kind"] == "memory_approval"
    assert item["memory_version_id"] is not None
    assert alerts[0][0][1] == "human_attention"

    # Memory remains owner-controlled even though it shares an inbox with
    # editor-resolvable business escalations.
    r = await client.post(
        f"/v1/work-items/{item['id']}/resolve",
        headers=bob,
        json={"resolution": "approved"},
    )
    assert r.status_code == 403
    r = await client.post(
        f"/v1/work-items/{item['id']}/resolve",
        headers=alice,
        json={"resolution": "approved"},
    )
    assert r.status_code == 200
    current = (await client.get(f"/v1/agents/{agent_id}/memory", headers=bob)).json()["current"]
    assert current["content"] == "# Notes\nCross-check unusual invoice amounts."


async def test_inbox_ui_renders_and_resolves_escalation(
    client: AsyncClient, risk_agent: dict
) -> None:
    agent = risk_agent["agent"]
    tenant_id = risk_agent["tenant"]["id"]
    async with get_sessionmaker()() as db:
        item = WorkItem(
            tenant_id=uuid.UUID(tenant_id),
            team_id=uuid.UUID(risk_agent["team"]["id"]),
            agent_id=uuid.UUID(agent["id"]),
            kind="human_escalation",
            title="Invoice needs billing review",
            details={
                "reason": "Amount is outside tolerance.",
                "severity": "high",
                "requested_action": "Approve or correct the invoice.",
            },
        )
        db.add(item)
        await db.commit()
        item_id = item.id

    login = await client.get("/ui/login")
    csrf = re.search(r'name="_csrf_token" value="([^"]+)"', login.text).group(1)
    await client.post(
        "/ui/login",
        data={"email": "bob@example.com", "password": "password-123", "_csrf_token": csrf},
    )
    page = await client.get(f"/ui/t/{tenant_id}/inbox")
    assert page.status_code == 200
    assert "Invoice needs billing review" in page.text
    assert "Amount is outside tolerance" in page.text
    csrf = re.search(r'name="_csrf_token" value="([^"]+)"', page.text).group(1)
    r = await client.post(
        f"/ui/work-items/{item_id}/resolve",
        data={
            "_csrf_token": csrf,
            "resolution": "resolved",
            "response": "Correct it, then send.",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    closed = await client.get(f"/ui/t/{tenant_id}/inbox?state=closed")
    assert "Correct it, then send." in closed.text
