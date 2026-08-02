"""Operational infrastructure: retention, concurrency caps, alerting gaps,
job listing/retry, health."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from sleeper_service import storage
from sleeper_service.config import get_settings
from sleeper_service.db.models import Job
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime import notify, runner
from sleeper_service.runtime.retention import PRUNED_MARKER, cleanup_tick
from tests.conftest import auth


async def _submit(client, headers, agent_id, prompt="assess", **kwargs):
    return await client.post(
        f"/v1/agents/{agent_id}/jobs",
        headers=headers,
        json={"context": {"prompt": prompt}, **kwargs},
    )


# --- Retention ---


async def test_file_ttl_and_job_retention(client: AsyncClient, risk_agent: dict, bootstrap) -> None:
    root = auth(bootstrap.superuser_key)
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]
    agent_id = risk_agent["agent"]["id"]

    r = await client.patch(
        f"/v1/tenants/{tenant_id}",
        headers=root,
        json={"settings": {"file_ttl_days": 7, "job_retention_days": 30}},
    )
    assert r.status_code == 200

    # upload stamps expires_at from tenant settings
    r = await client.post(
        f"/v1/files?tenant_id={tenant_id}",
        headers=bob,
        files={"file": ("doomed.txt", b"bye", "text/plain")},
    )
    file = r.json()
    assert file["expires_at"] is not None

    # force-expire it, plus create an old job to be pruned
    async with get_sessionmaker()() as db:
        row = await db.get(
            __import__("sleeper_service.db.models", fromlist=["File"]).File, uuid.UUID(file["id"])
        )
        row.expires_at = datetime.now(UTC) - timedelta(hours=1)
        old_job = Job(
            agent_id=uuid.UUID(agent_id),
            agent_version_id=uuid.UUID(risk_agent["version"]["id"]),
            status="succeeded",
            payload={"prompt": "ancient"},
            output={"risk_level": "low"},
            created_at=datetime.now(UTC) - timedelta(days=60),
        )
        db.add(old_job)
        await db.commit()
        old_job_id = old_job.id

    stats = await cleanup_tick()
    assert stats["files_deleted"] >= 1
    assert stats["jobs_pruned"] >= 1

    assert (await client.get(f"/v1/files/{file['id']}", headers=bob)).status_code == 404
    with pytest.raises(FileNotFoundError):
        await storage.get_object(file["object_key"])

    job = (await client.get(f"/v1/jobs/{old_job_id}", headers=bob)).json()
    assert job["payload"] == PRUNED_MARKER
    assert job["output"] is None
    assert job["status"] == "succeeded"  # audit fields survive


# --- Concurrency caps ---


async def test_tenant_concurrency_cap_defers(
    client: AsyncClient, risk_agent: dict, bootstrap
) -> None:
    from sleeper_service.worker import _tenant_at_capacity, run_job

    root = auth(bootstrap.superuser_key)
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    tenant_id = risk_agent["tenant"]["id"]
    agent_id = risk_agent["agent"]["id"]

    await client.patch(
        f"/v1/tenants/{tenant_id}",
        headers=root,
        json={"settings": {"max_concurrent_jobs": 1}},
    )

    r1 = await _submit(client, bob, agent_id)
    r2 = await _submit(client, bob, agent_id)
    running_id, queued_id = r1.json()["id"], r2.json()["id"]
    async with get_sessionmaker()() as db:
        job = await db.get(Job, uuid.UUID(running_id))
        job.status = "running"
        await db.commit()

    assert await _tenant_at_capacity(queued_id) is True

    deferred: list[tuple] = []

    class FakeRedis:
        async def enqueue_job(self, fn, *args, **kwargs):
            deferred.append((fn, args, kwargs))

    await run_job({"job_try": 1, "redis": FakeRedis()}, queued_id)
    assert deferred and deferred[0][0] == "run_job"
    assert deferred[0][2].get("_defer_by") == 10
    # job untouched — still queued, no execution happened
    job = (await client.get(f"/v1/jobs/{queued_id}", headers=bob)).json()
    assert job["status"] == "queued"

    # capacity freed → runs normally
    async with get_sessionmaker()() as db:
        job = await db.get(Job, uuid.UUID(running_id))
        job.status = "succeeded"
        await db.commit()
    assert await _tenant_at_capacity(queued_id) is False


# --- Alerting gaps ---


async def test_callback_failure_notifies(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx as httpx_mod

    import sleeper_service.worker as worker_mod
    from sleeper_service.runtime import callbacks

    bob = auth(risk_agent["users"]["bob"]["api_key"])
    r = await _submit(
        client, bob, risk_agent["agent"]["id"], callback_url="https://down.example/hook"
    )
    job_id = r.json()["id"]
    await runner.execute_job(uuid.UUID(job_id))

    real_client = httpx_mod.AsyncClient

    def failing_client(**kwargs):
        return real_client(transport=httpx_mod.MockTransport(lambda req: httpx_mod.Response(502)))

    sent: list[str] = []

    async def fake_notify(agent_id, event_type, title, body):
        sent.append(event_type)

    monkeypatch.setattr(callbacks.httpx, "AsyncClient", failing_client)
    monkeypatch.setattr(worker_mod.notify, "notify", fake_notify)

    await worker_mod.deliver_callback({"job_try": get_settings().callback_max_tries}, job_id)
    assert sent == ["callback_failed"]


async def test_error_rate_alert(
    client: AsyncClient, risk_agent: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent_id = uuid.UUID(risk_agent["agent"]["id"])
    version_id = uuid.UUID(risk_agent["version"]["id"])

    sent: list[str] = []

    async def fake_notify(agent, event_type, title, body):
        sent.append(event_type)

    monkeypatch.setattr(notify, "notify", fake_notify)

    async def add_jobs(n: int, status: str) -> None:
        async with get_sessionmaker()() as db:
            for _ in range(n):
                db.add(
                    Job(
                        agent_id=agent_id,
                        agent_version_id=version_id,
                        status=status,
                        payload={"prompt": "x"},
                    )
                )
            await db.commit()

    # below minimum sample: silent
    await add_jobs(5, "failed")
    await notify.check_error_rate(agent_id)
    assert sent == []

    # 10 failed of 12 → alert
    await add_jobs(5, "failed")
    await add_jobs(2, "succeeded")
    await notify.check_error_rate(agent_id)
    assert sent == ["error_rate"]


# --- Job listing + retry ---


async def test_job_listing_and_pagination(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    dave = auth(risk_agent["users"]["dave"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    ids = []
    for i in range(5):
        r = await _submit(client, bob, agent_id, prompt=f"job {i}")
        ids.append(r.json()["id"])
    await runner.execute_job(uuid.UUID(ids[0]))

    r = await client.get(f"/v1/agents/{agent_id}/jobs", headers=carol)
    assert r.status_code == 200
    assert len(r.json()) == 5
    assert r.json()[0]["id"] == ids[-1]  # newest first

    r = await client.get(f"/v1/agents/{agent_id}/jobs?status=succeeded", headers=carol)
    assert [j["id"] for j in r.json()] == [ids[0]]

    r = await client.get(f"/v1/agents/{agent_id}/jobs?limit=2&offset=2", headers=carol)
    assert len(r.json()) == 2

    assert (await client.get(f"/v1/agents/{agent_id}/jobs", headers=dave)).status_code == 404


async def test_dead_letter_retry(client: AsyncClient, risk_agent: dict) -> None:
    bob = auth(risk_agent["users"]["bob"]["api_key"])
    carol = auth(risk_agent["users"]["carol"]["api_key"])
    agent_id = risk_agent["agent"]["id"]

    r = await _submit(client, bob, agent_id)
    job_id = r.json()["id"]
    await runner.mark_job(uuid.UUID(job_id), "dead_letter", "retries exhausted: 503")

    # viewer cannot retry (submitting rights required)
    assert (await client.post(f"/v1/jobs/{job_id}/retry", headers=carol)).status_code == 403

    r = await client.post(f"/v1/jobs/{job_id}/retry", headers=bob)
    assert r.status_code == 202
    assert r.json()["status"] == "queued"
    assert r.json()["error"] is None
    events = (await client.get(f"/v1/jobs/{job_id}/events", headers=bob)).json()
    assert "retried" in [e["type"] for e in events]

    # run it and confirm a successful rerun can't be retried again
    await runner.execute_job(uuid.UUID(job_id))
    assert (await client.post(f"/v1/jobs/{job_id}/retry", headers=bob)).status_code == 409


# --- Health ---


async def test_healthz_checks_dependencies(client: AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["postgres"] == "ok"
    assert body["redis"] == "ok"


def test_init_refuses_placeholder_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    import typer

    from sleeper_service.cli.main import init

    monkeypatch.setattr(get_settings(), "secret_key", "change-me")
    with pytest.raises(typer.Exit):
        init(tenant_name="x", email="a@b.c", password="password-123")
    monkeypatch.setattr(get_settings(), "secret_key", "test-secret-key-long-enough")
