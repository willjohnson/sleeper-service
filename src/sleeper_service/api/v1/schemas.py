import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from sleeper_service.constants import KeyScope, Role


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Tenants ---


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    system_prompt: str = ""


class TenantUpdate(BaseModel):
    system_prompt: str | None = None
    settings: dict | None = None


class TenantOut(OrmModel):
    id: uuid.UUID
    name: str
    system_prompt: str
    settings: dict
    created_at: datetime


# --- Users ---


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    is_superuser: bool = False


class UserOut(OrmModel):
    id: uuid.UUID
    email: str
    is_superuser: bool
    created_at: datetime


class UserWithKeyOut(UserOut):
    api_key: str  # plaintext, shown once


class MeOut(UserOut):
    roles: dict[uuid.UUID, Role]


# --- Teams ---


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # Defaults to the caller; every team must have an owner from birth.
    owner_user_id: uuid.UUID | None = None


class TeamOut(OrmModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    is_org_team: bool
    created_at: datetime


class MemberSet(BaseModel):
    role: Role


class MemberOut(OrmModel):
    user_id: uuid.UUID
    team_id: uuid.UUID
    role: Role


# --- Agents ---


class AgentCreate(BaseModel):
    team_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    spending_limit: Decimal | None = None
    options: dict = Field(default_factory=dict)


class AgentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    spending_limit: Decimal | None = None
    options: dict | None = None


class AgentOut(OrmModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    team_id: uuid.UUID
    name: str
    description: str
    parent_agent_id: uuid.UUID | None
    current_version_id: uuid.UUID | None
    spending_limit: Decimal | None
    options: dict
    created_at: datetime
    updated_at: datetime


# --- API keys ---


class InvokeKeyCreate(BaseModel):
    scope: KeyScope
    scope_id: uuid.UUID
    name: str = ""
    rate_limit: int | None = Field(default=None, ge=1)


class ApiKeyOut(OrmModel):
    id: uuid.UUID
    kind: str
    user_id: uuid.UUID | None
    scope: KeyScope | None
    scope_id: uuid.UUID | None
    name: str
    rate_limit: int | None
    created_at: datetime
    revoked_at: datetime | None


class ApiKeyWithSecretOut(ApiKeyOut):
    api_key: str  # plaintext, shown once


# --- Models registry ---


class ModelCreate(BaseModel):
    provider: str = Field(min_length=1)
    name: str = Field(min_length=1)
    # pydantic-ai model string, e.g. anthropic:claude-sonnet-5
    model_string: str = Field(min_length=1)


class ModelOut(OrmModel):
    id: uuid.UUID
    provider: str
    name: str
    model_string: str


# --- Provider credentials ---


class ProviderCredSet(BaseModel):
    api_key: str = Field(min_length=1)


class ProviderCredOut(OrmModel):
    id: uuid.UUID
    scope: KeyScope
    scope_id: uuid.UUID
    provider: str
    created_at: datetime
    # credentials are never returned


# --- Agent versions ---


class VersionCreate(BaseModel):
    prompt: str = Field(min_length=1)
    model: str  # models.model_string or "provider/name"
    params: dict = Field(default_factory=dict)
    max_iterations: int = Field(default=10, ge=1, le=100)
    timeout_s: int = Field(default=300, ge=1, le=3600)
    tool_grants: list = Field(default_factory=list)
    data_store_grants: list = Field(default_factory=list)
    input_schema: dict | None = None
    output_schema: dict | None = None


class VersionOut(OrmModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    version_no: int
    prompt: str
    model_id: uuid.UUID | None
    params: dict
    max_iterations: int
    timeout_s: int
    tool_grants: list
    data_store_grants: list
    input_schema: dict | None
    output_schema: dict | None
    created_by: uuid.UUID | None
    created_at: datetime


class PromoteRequest(BaseModel):
    version_no: int = Field(ge=1)


# --- Files ---


class FileOut(OrmModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    object_key: str
    size: int
    content_type: str
    expires_at: datetime | None
    created_at: datetime


# --- Jobs ---


class JobContext(BaseModel):
    prompt: str = Field(min_length=1)
    files: list[uuid.UUID] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)  # fetched in Phase 2 (allowlist)


class JobSubmit(BaseModel):
    context: JobContext
    callback_url: str | None = None
    agent_version_id: uuid.UUID | None = None  # pin an exact version
    version_no: int | None = None  # or pin by number
    idempotency_key: str | None = Field(default=None, max_length=200)
    user_ctx: dict | None = None


class JobOut(OrmModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    agent_version_id: uuid.UUID
    parent_job_id: uuid.UUID | None
    status: str
    payload: dict
    output: dict | None
    error: str | None
    tokens_in: int
    tokens_out: int
    cost: Decimal
    callback_url: str | None
    user_ctx: dict | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    # present when the agent has learning enabled; single-job-scoped signed URL
    feedback_url: str | None = None


class JobEventOut(OrmModel):
    id: int
    job_id: uuid.UUID
    ts: datetime
    type: str
    data: dict


# --- MCP servers ---


class McpServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # streamable_http/sse: endpoint is the URL. stdio: endpoint is the command line.
    endpoint: str = Field(min_length=1)
    transport: str = Field(pattern="^(streamable_http|sse|stdio)$")
    # {"headers": {"Authorization": "Bearer ..."}} — encrypted at rest
    credentials: dict | None = None


class McpServerOut(OrmModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    endpoint: str
    transport: str
    created_at: datetime
    # credentials are never returned


# --- Data stores ---


class DataStoreCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(pattern="^(s3|azure_blob|gcs|box|local)$")
    # s3: {"bucket": ..., "endpoint_url": optional}; local: {"base_path": ...}
    config: dict = Field(default_factory=dict)
    # s3: {"access_key": ..., "secret_key": ...} — encrypted at rest
    credentials: dict | None = None


class DataStoreOut(OrmModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    type: str
    config: dict
    created_at: datetime


# --- Notification channels ---


class NotifChannelCreate(BaseModel):
    apprise_url: str = Field(min_length=1)  # e.g. slack://..., mailto://..., json://...
    events: list[str] = Field(min_length=1)


class NotifChannelOut(OrmModel):
    id: uuid.UUID
    team_id: uuid.UUID
    events: list
    created_at: datetime
    # the apprise URL embeds credentials and is never returned


# --- Event sources ---


class EventSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_agent_id: uuid.UUID
    # {{path.to.field}} substitution against the event body; {{body}} = whole
    # body as JSON. Example: {"prompt": "Price event: {{body}}"}
    payload_template: dict = Field(default_factory=lambda: {"prompt": "{{body}}"})
    dedup_key_path: str | None = None
    config: dict = Field(default_factory=dict)


class EventSourceOut(OrmModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    target_agent_id: uuid.UUID
    payload_template: dict
    dedup_key_path: str | None
    config: dict
    created_at: datetime


class EventSourceWithSecretOut(EventSourceOut):
    secret: str  # shown once


class EventAccepted(BaseModel):
    job_id: uuid.UUID
    deduped: bool = False


# --- Spend ---


class SpendOut(BaseModel):
    agent_id: uuid.UUID
    month_start: datetime
    spend: Decimal
    spending_limit: Decimal | None


# --- Phase 3: trees, feedback, memory ---


class JobTreeOut(JobOut):
    children: list["JobTreeOut"] = Field(default_factory=list)


class FeedbackCreate(BaseModel):
    vote: int = Field(description="+1 or -1")
    comment: str | None = Field(default=None, max_length=2000)

    @field_validator("vote")
    @classmethod
    def _vote_range(cls, v: int) -> int:
        if v not in (1, -1):
            raise ValueError("vote must be 1 or -1")
        return v


class FeedbackOut(OrmModel):
    id: uuid.UUID
    job_id: uuid.UUID
    vote: int
    comment: str | None
    created_at: datetime


class MemoryVersionOut(OrmModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    version_no: int
    source_job_id: uuid.UUID | None
    created_at: datetime


class MemoryVersionWithContentOut(MemoryVersionOut):
    content: str


class AgentMemoryOut(BaseModel):
    current: MemoryVersionWithContentOut | None
    versions: list[MemoryVersionOut]
