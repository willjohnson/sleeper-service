"""Test setup: a dedicated `sleeper_test` database on the compose Postgres.

Environment is pinned before any app import so `get_settings()` caches the
test values. All tests share one event loop (and therefore one engine).
"""

import os
import uuid

os.environ["DATABASE_URL"] = "postgresql+asyncpg://sleeper:sleeper@localhost:5433/sleeper_test"
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.passwords import hash_password
from sleeper_service.constants import KeyKind, Role
from sleeper_service.db.base import Base
from sleeper_service.db.models import ApiKey, Team, TeamMember, Tenant, User
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.main import app


@pytest.fixture(scope="session", autouse=True)
async def _database() -> None:
    admin = await asyncpg.connect("postgresql://sleeper:sleeper@localhost:5433/sleeper")
    exists = await admin.fetchval("SELECT 1 FROM pg_database WHERE datname = 'sleeper_test'")
    if not exists:
        await admin.execute("CREATE DATABASE sleeper_test")
    await admin.close()

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.bind.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture(autouse=True)
async def _clean_tables(_database: None) -> None:
    async with get_sessionmaker()() as session:
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(delete(table))
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
