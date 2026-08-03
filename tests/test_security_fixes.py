import uuid
import pytest
from unittest.mock import AsyncMock, patch
from pydantic_ai import ModelRetry

from sleeper_service.db.models import DataStore, Job
from sleeper_service.runtime.toolsets import _StoreGrant
from sleeper_service.runtime.links import fetch_links
from sleeper_service.runtime.delegation import _ancestry


def test_store_grant_resolve_path_traversal():
    store = DataStore(id=uuid.uuid4(), name="test_store", type="local", config={"base_path": "/tmp"})
    
    # 1. Empty prefix grant
    grant_empty = _StoreGrant(store, prefix="", mode="ro")
    assert grant_empty.resolve("valid/path.txt") == "valid/path.txt"
    assert grant_empty.resolve("") == "."
    
    with pytest.raises(ModelRetry) as exc_info:
        grant_empty.resolve("../../etc/passwd")
    assert "escapes the granted prefix" in str(exc_info.value)

    with pytest.raises(ModelRetry) as exc_info:
        grant_empty.resolve("../secret")
    assert "escapes the granted prefix" in str(exc_info.value)

    # 2. Non-empty prefix grant
    grant_reports = _StoreGrant(store, prefix="reports", mode="ro")
    assert grant_reports.resolve("2026/jan.txt") == "reports/2026/jan.txt"
    
    with pytest.raises(ModelRetry) as exc_info:
        grant_reports.resolve("../other/secret.txt")
    assert "escapes the granted prefix" in str(exc_info.value)

    with pytest.raises(ModelRetry) as exc_info:
        grant_reports.resolve("../../secret.txt")
    assert "escapes the granted prefix" in str(exc_info.value)


def test_store_grant_resolve_is_cwd_independent(monkeypatch):
    # relpath()-style checks consult os.getcwd(); from "/" they'd let an
    # empty-prefix grant escape. The check must be pure string logic.
    monkeypatch.chdir("/")
    store = DataStore(id=uuid.uuid4(), name="test_store", type="local", config={"base_path": "/tmp"})
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
        if jid == job1_id:
            return job1
        if jid == job2_id:
            return job2
        return None
    db.get.side_effect = get_job

    depth, agent_ids = await _ancestry(db, job1)
    assert depth == 1
    assert agent_id in agent_ids


@pytest.mark.asyncio
async def test_ssrf_redirect_blocked():
    import httpx

    async def mock_get(url, follow_redirects=False):
        if url == "https://allowed.example.com/redirect":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200, text="meta-data")

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        settings = {"link_allowlist": ["allowed.example.com"]}
        blocks = await fetch_links(["https://allowed.example.com/redirect"], settings)

        assert len(blocks) == 1
        assert "host not in tenant allowlist" in blocks[0]


@pytest.mark.asyncio
async def test_fetch_links_denies_all_without_allowlist():
    # Mirror check_links: no link_allowlist configured means deny-by-default,
    # even if a job with links somehow reaches the fetch stage.
    import httpx

    async def mock_get(url, follow_redirects=False):  # pragma: no cover - must not be reached
        raise AssertionError("no request should be made without an allowlist")

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        for settings in (None, {}):
            blocks = await fetch_links(["https://anything.example.com/"], settings)
            assert len(blocks) == 1
            assert "host not in tenant allowlist" in blocks[0]
