import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

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
