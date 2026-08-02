"""Memory governance: pending-approval queue and rollback (team owners).

With options.memory_approval on, every memory write — agent proposals and
feedback folds — waits here. Approve to make it the injected version (its
gating eval run, if any, shows the pass rate first); reject to discard.
Rollback retires the latest active version so the previous one takes over.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.agents import _get_visible_agent
from sleeper_service.api.v1.schemas import EvalRunOut, MemoryVersionWithContentOut
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.db.models import EvalRun, MemoryVersion
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/agents/{agent_id}/memory", tags=["memory-governance"])


async def _get_version(db: AsyncSession, agent_id: uuid.UUID, version_no: int) -> MemoryVersion:
    version = await db.scalar(
        select(MemoryVersion).where(
            MemoryVersion.agent_id == agent_id, MemoryVersion.version_no == version_no
        )
    )
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return version


@router.get("/pending")
async def list_pending_memory(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[dict]:
    """Pending memory versions, each with its gating eval run (if any)."""
    await _get_visible_agent(agent_id, db, principal)
    pending = list(
        await db.scalars(
            select(MemoryVersion)
            .where(MemoryVersion.agent_id == agent_id, MemoryVersion.status == "pending")
            .order_by(MemoryVersion.version_no)
        )
    )
    out = []
    for version in pending:
        gate_run = await db.scalar(
            select(EvalRun)
            .where(EvalRun.memory_version_id == version.id)
            .order_by(EvalRun.created_at.desc())
            .limit(1)
        )
        out.append(
            {
                "version": MemoryVersionWithContentOut.model_validate(version).model_dump(
                    mode="json"
                ),
                "eval_run": EvalRunOut.model_validate(gate_run).model_dump(mode="json")
                if gate_run
                else None,
            }
        )
    return out


@router.post("/{version_no}/approve", response_model=MemoryVersionWithContentOut)
async def approve_memory(
    agent_id: uuid.UUID,
    version_no: int,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> MemoryVersion:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    version = await _get_version(db, agent_id, version_no)
    if version.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Version is {version.status}")
    version.status = "active"
    await db.commit()
    await db.refresh(version)
    return version


@router.post("/{version_no}/reject", response_model=MemoryVersionWithContentOut)
async def reject_memory(
    agent_id: uuid.UUID,
    version_no: int,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> MemoryVersion:
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    version = await _get_version(db, agent_id, version_no)
    if version.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Version is {version.status}")
    version.status = "rejected"
    await db.commit()
    await db.refresh(version)
    return version


@router.post("/rollback")
async def rollback_memory(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> dict:
    """Retire the latest active version; the previous active one takes over."""
    agent = await _get_visible_agent(agent_id, db, principal)
    require_role(principal, agent.team_id, Role.OWNER)
    latest = await db.scalar(
        select(MemoryVersion)
        .where(MemoryVersion.agent_id == agent_id, MemoryVersion.status == "active")
        .order_by(MemoryVersion.version_no.desc())
        .limit(1)
    )
    if latest is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "No active memory to roll back")
    latest.status = "rejected"
    await db.commit()
    new_latest = await db.scalar(
        select(MemoryVersion)
        .where(MemoryVersion.agent_id == agent_id, MemoryVersion.status == "active")
        .order_by(MemoryVersion.version_no.desc())
        .limit(1)
    )
    return {
        "rolled_back_version_no": latest.version_no,
        "now_active_version_no": new_latest.version_no if new_latest else None,
    }
