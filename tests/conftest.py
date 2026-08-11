"""Test setup: a dedicated `sleeper_test` database on the compose Postgres.

Environment is pinned before any app import so `get_settings()` caches the
test values. All tests share one event loop (and therefore one engine).
"""

import os
import uuid


def _from_env(name: str, default: str) -> str:
    """A setting from the environment or the local .env: compose host-port
    overrides (machines whose standard ports are occupied set these there) and
    the MinIO credentials, which tests share with the running container."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        with open(".env") as fh:
            for line in fh:
                if line.startswith(f"{name}="):
                    return line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return default


_PG = _from_env("POSTGRES_HOST_PORT", "5432")
_REDIS = _from_env("REDIS_HOST_PORT", "6379")

os.environ["DATABASE_URL"] = f"postgresql+asyncpg://sleeper:sleeper@localhost:{_PG}/sleeper_test"
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ["SESSION_HTTPS_ONLY"] = "false"
# OIDC_ALLOW_LOOPBACK_ISSUERS stays at its production default (false) so issuer
# validation is exercised as deployed; the stub-IdP `idp` fixture turns it on.
# Redis db 1: isolates test enqueues/rate-limit counters from the compose worker (db 0)
os.environ["REDIS_URL"] = f"redis://localhost:{_REDIS}/1"
os.environ["MINIO_BUCKET"] = "sleeper-files-test"
# No shipped default any more (audit-4 housekeeping): tests must use whatever
# the MinIO they talk to was started with.
os.environ["MINIO_ACCESS_KEY"] = _from_env("MINIO_ACCESS_KEY", "sleeper")
os.environ["MINIO_SECRET_KEY"] = _from_env("MINIO_SECRET_KEY", "sleeper-minio-secret")
os.environ["LANGFUSE_HOST"] = ""  # never export test traces (overrides .env)

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.passwords import hash_password
from sleeper_service.constants import KeyKind, Role
from sleeper_service.db.base import Base
from sleeper_service.db.models import ApiKey, Team, TeamMember, Tenant, User
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.main import app


@pytest.fixture(scope="session", autouse=True)
async def _database() -> None:
    admin = await asyncpg.connect(f"postgresql://sleeper:sleeper@localhost:{_PG}/sleeper")
    exists = await admin.fetchval("SELECT 1 FROM pg_database WHERE datname = 'sleeper_test'")
    if not exists:
        await admin.execute("CREATE DATABASE sleeper_test")
    await admin.close()

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.bind.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    # ASGITransport skips lifespan, so create the test bucket here
    from sleeper_service import storage

    await storage.ensure_bucket()


@pytest.fixture(autouse=True)
async def _clean_tables(_database: None) -> None:
    # TRUNCATE ... CASCADE in one statement: handles the agents ↔ agent_versions
    # FK cycle that row-by-row deletes cannot.
    names = ", ".join(t.name for t in Base.metadata.sorted_tables)
    async with get_sessionmaker()() as session:
        await session.execute(text(f"TRUNCATE {names} CASCADE"))
        await session.commit()


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class Bootstrap:
    """Mirrors `sleeper init`: tenant, org team, superuser, bootstrap key."""

    def __init__(self) -> None:
        self.tenant_id: uuid.UUID | None = None
        self.org_team_id: uuid.UUID | None = None
        self.superuser_id: uuid.UUID | None = None
        self.superuser_key: str | None = None


@pytest.fixture
async def bootstrap() -> Bootstrap:
    b = Bootstrap()
    async with get_sessionmaker()() as db:
        tenant = Tenant(name="default")
        db.add(tenant)
        await db.flush()
        team = Team(tenant_id=tenant.id, name="org", is_org_team=True)
        user = User(
            email="root@example.com",
            password_hash=hash_password("root-password"),
            is_superuser=True,
        )
        db.add_all([team, user])
        await db.flush()
        db.add(TeamMember(user_id=user.id, team_id=team.id, role=Role.OWNER))
        plaintext, key_hash = generate_key(KeyKind.USER)
        db.add(ApiKey(kind=KeyKind.USER, user_id=user.id, key_hash=key_hash))
        await db.commit()
        b.tenant_id = tenant.id
        b.org_team_id = team.id
        b.superuser_id = user.id
        b.superuser_key = plaintext
    return b


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
async def org(client: AsyncClient, bootstrap: Bootstrap) -> dict:
    """A tenant with a 'risk' team and users alice (owner), bob (editor),
    carol (viewer), dave (no membership)."""
    root = auth(bootstrap.superuser_key)

    r = await client.post("/v1/tenants", headers=root, json={"name": "acme"})
    assert r.status_code == 201
    tenant = r.json()

    users = {}
    for name in ("alice", "bob", "carol", "dave"):
        r = await client.post(
            "/v1/users",
            headers=root,
            json={"email": f"{name}@example.com", "password": "password-123"},
        )
        assert r.status_code == 201
        users[name] = r.json()

    r = await client.post(
        f"/v1/tenants/{tenant['id']}/teams",
        headers=root,
        json={"name": "risk", "owner_user_id": users["alice"]["id"]},
    )
    assert r.status_code == 201
    team = r.json()

    alice = auth(users["alice"]["api_key"])
    for name, role in (("bob", "editor"), ("carol", "viewer")):
        r = await client.put(
            f"/v1/teams/{team['id']}/members/{users[name]['id']}",
            headers=alice,
            json={"role": role},
        )
        assert r.status_code == 200

    return {"tenant": tenant, "team": team, "users": users}


RISK_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
        "factors": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
    "required": ["risk_level", "factors", "summary"],
}


@pytest.fixture
async def seeded_models(bootstrap: Bootstrap) -> None:
    from sleeper_service.db.models import Model

    async with get_sessionmaker()() as db:
        db.add(Model(provider="test", name="default", model_string="test:default"))
        db.add(Model(provider="test", name="flaky", model_string="test:flaky"))
        db.add(
            Model(
                provider="anthropic",
                name="claude-sonnet-5",
                model_string="anthropic:claude-sonnet-5",
            )
        )
        await db.commit()


@pytest.fixture
async def risk_agent(client: AsyncClient, org: dict, seeded_models: None) -> dict:
    """An agent with one promoted version on the test model, typed output."""
    bob = auth(org["users"]["bob"]["api_key"])
    r = await client.post(
        "/v1/agents",
        headers=bob,
        json={
            "team_id": org["team"]["id"],
            "name": "risk-analyzer",
            "description": "Assess business risk",
        },
    )
    assert r.status_code == 201
    agent = r.json()
    r = await client.post(
        f"/v1/agents/{agent['id']}/versions",
        headers=bob,
        json={
            "prompt": "Assess business risk for the event in the payload.",
            "model": "test/default",
            "output_schema": RISK_SCHEMA,
        },
    )
    assert r.status_code == 201
    return {"agent": agent, "version": r.json(), **org}
