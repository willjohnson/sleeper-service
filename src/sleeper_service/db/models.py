"""Full Sleeper Service schema (docs/BUILD_PLAN.md § Data model).

Phase 0 uses a subset (tenants, users, teams, team_members, agents, api_keys);
the rest of the tables exist from the start so migrations track one lineage.

Enum-like columns are plain strings constrained by CHECK constraints — Python
enums in `constants.py` are the source of truth — to keep Alembic diffs free of
native-enum churn.
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    Numeric,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sleeper_service.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPKMixin


class Tenant(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(unique=True)
    system_prompt: Mapped[str] = mapped_column(Text, default="")
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)


class User(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str | None]
    is_superuser: Mapped[bool] = mapped_column(default=False)

    memberships: Mapped[list["TeamMember"]] = relationship(back_populates="user")


class Team(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str]
    is_org_team: Mapped[bool] = mapped_column(default=False)

    members: Mapped[list["TeamMember"]] = relationship(back_populates="team")


class TeamMember(Base):
    __tablename__ = "team_members"
    __table_args__ = (
        CheckConstraint("role IN ('owner', 'editor', 'viewer')", name="role_valid"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str]

    user: Mapped["User"] = relationship(back_populates="memberships")
    team: Mapped["Team"] = relationship(back_populates="members")


class Agent(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), index=True)
    name: Mapped[str]
    description: Mapped[str] = mapped_column(Text, default="")
    parent_agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id"))
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_versions.id", use_alter=True, name="fk_agents_current_version")
    )
    spending_limit: Mapped[Decimal | None] = mapped_column(Numeric(12, 4))
    options: Mapped[dict] = mapped_column(JSONB, default=dict)


class AgentVersion(UUIDPKMixin, Base):
    __tablename__ = "agent_versions"
    __table_args__ = (UniqueConstraint("agent_id", "version_no"),)

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    version_no: Mapped[int]
    prompt: Mapped[str] = mapped_column(Text)
    model_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("models.id"))
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    max_iterations: Mapped[int] = mapped_column(default=10)
    timeout_s: Mapped[int] = mapped_column(default=300)
    tool_grants: Mapped[list] = mapped_column(JSONB, default=list)
    data_store_grants: Mapped[list] = mapped_column(JSONB, default=list)
    input_schema: Mapped[dict | None] = mapped_column(JSONB)
    output_schema: Mapped[dict | None] = mapped_column(JSONB)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Model(UUIDPKMixin, Base):
    __tablename__ = "models"
    __table_args__ = (UniqueConstraint("provider", "name"),)

    provider: Mapped[str]
    name: Mapped[str]
    model_string: Mapped[str]


class McpServer(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str]
    endpoint: Mapped[str]
    transport: Mapped[str]
    credentials_enc: Mapped[bytes | None] = mapped_column(LargeBinary)


class DataStore(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "data_stores"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name"),
        CheckConstraint(
            "type IN ('s3', 'azure_blob', 'gcs', 'box', 'local')", name="type_valid"
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str]
    type: Mapped[str]
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    credentials_enc: Mapped[bytes | None] = mapped_column(LargeBinary)


class ApiKey(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        CheckConstraint("kind IN ('user', 'invoke')", name="kind_valid"),
        CheckConstraint(
            "(kind = 'user' AND user_id IS NOT NULL AND scope IS NULL AND scope_id IS NULL)"
            " OR "
            "(kind = 'invoke' AND user_id IS NULL AND scope IS NOT NULL AND scope_id IS NOT NULL)",
            name="kind_shape",
        ),
        CheckConstraint(
            "scope IS NULL OR scope IN ('tenant', 'team', 'agent')", name="scope_valid"
        ),
    )

    kind: Mapped[str]
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    scope: Mapped[str | None]
    scope_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    key_hash: Mapped[str] = mapped_column(unique=True)
    name: Mapped[str] = mapped_column(default="")
    rate_limit: Mapped[int | None]
    revoked_at: Mapped[datetime | None]


class ProviderCred(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "provider_creds"
    __table_args__ = (
        CheckConstraint("scope IN ('tenant', 'team', 'agent')", name="scope_valid"),
        UniqueConstraint("scope", "scope_id", "provider"),
    )

    scope: Mapped[str]
    scope_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    provider: Mapped[str]
    credentials_enc: Mapped[bytes] = mapped_column(LargeBinary)


class File(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "files"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    object_key: Mapped[str] = mapped_column(unique=True)
    size: Mapped[int] = mapped_column(BigInteger)
    content_type: Mapped[str]
    expires_at: Mapped[datetime | None]


class Job(UUIDPKMixin, Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("agent_id", "idempotency_key"),
        Index("ix_jobs_agent_created", "agent_id", "created_at"),
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"))
    agent_version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_versions.id"))
    memory_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("memory_versions.id", use_alter=True, name="fk_jobs_memory_version")
    )
    parent_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id"), index=True)
    status: Mapped[str] = mapped_column(default="queued", index=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    output: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    tokens_in: Mapped[int] = mapped_column(default=0)
    tokens_out: Mapped[int] = mapped_column(default=0)
    cost: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal(0))
    callback_url: Mapped[str | None]
    user_ctx: Mapped[dict | None] = mapped_column(JSONB)
    idempotency_key: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class JobEvent(Base):
    __tablename__ = "job_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), index=True
    )
    ts: Mapped[datetime] = mapped_column(server_default=func.now())
    type: Mapped[str]
    data: Mapped[dict] = mapped_column(JSONB, default=dict)


class EventSource(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "event_sources"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str]
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    target_agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"))
    payload_template: Mapped[dict] = mapped_column(JSONB, default=dict)
    secret_hash: Mapped[str]
    dedup_key_path: Mapped[str | None]


class NotifChannel(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "notif_channels"

    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    apprise_url_enc: Mapped[bytes] = mapped_column(LargeBinary)
    events: Mapped[list] = mapped_column(JSONB, default=list)


class MemoryVersion(UUIDPKMixin, Base):
    __tablename__ = "memory_versions"
    __table_args__ = (UniqueConstraint("agent_id", "version_no"),)

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    version_no: Mapped[int]
    content: Mapped[str] = mapped_column(Text)
    source_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Feedback(UUIDPKMixin, CreatedAtMixin, Base):
    __tablename__ = "feedback"
    __table_args__ = (CheckConstraint("vote IN (-1, 1)", name="vote_valid"),)

    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), index=True
    )
    vote: Mapped[int] = mapped_column(SmallInteger)
    comment: Mapped[str | None] = mapped_column(Text)
