"""Unified human-work inbox.

Any team member can see their team's items. Memory changes remain owner-gated;
editors and owners can resolve an agent's business-level escalation.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import WorkItemOut, WorkItemResolve
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role, visible_team_ids
from sleeper_service.constants import Role
from sleeper_service.db.models import Tenant, WorkItem
from sleeper_service.db.session import get_db
from sleeper_service.runtime.work_items import WorkItemConflict, resolve_work_item

router = APIRouter(tags=["human-work"])


async def _visible_item(
    db: AsyncSession,
    principal: UserPrincipal,
    item_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> WorkItem:
    stmt = select(WorkItem).where(WorkItem.id == item_id)
    if for_update:
        stmt = stmt.with_for_update()
    item = await db.scalar(stmt)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    require_role(principal, item.team_id, Role.VIEWER)
    return item


@router.get("/tenants/{tenant_id}/work-items", response_model=list[WorkItemOut])
async def list_work_items(
    tenant_id: uuid.UUID,
    item_status: str = Query("open", alias="status"),
    kind: str | None = None,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[WorkItem]:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    team_ids = await visible_team_ids(db, principal, tenant_id)
    if not team_ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    stmt = select(WorkItem).where(WorkItem.tenant_id == tenant_id, WorkItem.team_id.in_(team_ids))
    if item_status != "all":
        if item_status not in ("open", "resolved", "dismissed"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown status")
        stmt = stmt.where(WorkItem.status == item_status)
    if kind is not None:
        if kind not in ("memory_approval", "human_escalation"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown kind")
        stmt = stmt.where(WorkItem.kind == kind)
    return list(await db.scalars(stmt.order_by(WorkItem.created_at.desc())))


@router.get("/work-items/{item_id}", response_model=WorkItemOut)
async def get_work_item(
    item_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> WorkItem:
    return await _visible_item(db, principal, item_id)


@router.post("/work-items/{item_id}/resolve", response_model=WorkItemOut)
async def resolve_item(
    item_id: uuid.UUID,
    body: WorkItemResolve,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> WorkItem:
    item = await _visible_item(db, principal, item_id)
    required = Role.OWNER if item.kind == "memory_approval" else Role.EDITOR
    require_role(principal, item.team_id, required)
    item = await _visible_item(db, principal, item_id, for_update=True)
    try:
        await resolve_work_item(
            db,
            item,
            resolution=body.resolution,
            response=body.response,
            resolved_by_user_id=principal.user.id,
        )
    except WorkItemConflict as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    await db.commit()
    await db.refresh(item)
    return item
