"""Tenant (org-wide) and team system prompts — the outer layers of the prompt
sandwich: tenant prompt → team prompt → agent prompt → memory.

Both are versioned like agent prompts and memory: every change appends an
immutable prompt_versions row, and every job pins the versions it ran with, so
agent version + prompt versions + memory version reproduce a job's
instructions exactly.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.db.models import PromptVersion, Team, Tenant


def _scope(owner: Tenant | Team) -> tuple[uuid.UUID, uuid.UUID | None]:
    """(tenant_id, team_id) of the prompt history an owner keeps."""
    if isinstance(owner, Team):
        return owner.tenant_id, owner.id
    return owner.id, None


def _where(owner: Tenant | Team) -> tuple:
    tenant_id, team_id = _scope(owner)
    team_clause = (
        PromptVersion.team_id.is_(None) if team_id is None else (PromptVersion.team_id == team_id)
    )
    return PromptVersion.tenant_id == tenant_id, team_clause


async def save_system_prompt(
    db: AsyncSession, owner: Tenant | Team, content: str, user_id: uuid.UUID | None
) -> PromptVersion | None:
    """Append a new version when the text differs from the live one.

    Saving the live text again is not a change, so it creates nothing — forms
    post the prompt alongside other fields on every save. Clearing a prompt
    is a change and is recorded as an empty version.
    """
    latest = await db.scalar(
        select(PromptVersion)
        .where(*_where(owner))
        .order_by(PromptVersion.version_no.desc())
        .limit(1)
    )
    if content == (latest.content if latest is not None else ""):
        return None
    tenant_id, team_id = _scope(owner)
    version = PromptVersion(
        tenant_id=tenant_id,
        team_id=team_id,
        version_no=(latest.version_no if latest is not None else 0) + 1,
        content=content,
        created_by=user_id,
    )
    db.add(version)
    return version


async def prompt_history(db: AsyncSession, owner: Tenant | Team) -> list[PromptVersion]:
    """Every version of an owner's prompt, newest first."""
    stmt = select(PromptVersion).where(*_where(owner)).order_by(PromptVersion.version_no.desc())
    return list(await db.scalars(stmt))


async def pinned_prompt(db: AsyncSession, version_id: uuid.UUID | None) -> str:
    """The text of a pinned version; no pin means no prompt at that layer."""
    if version_id is None:
        return ""
    version = await db.get(PromptVersion, version_id)
    return version.content if version is not None else ""
