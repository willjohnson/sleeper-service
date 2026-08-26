"""Notification channels (BUILD_PLAN § Notifications & alerting): team owners
configure Apprise URLs subscribed to alert event types."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import NotifChannelCreate, NotifChannelOut
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import NotifChannel, Team, Tenant
from sleeper_service.db.session import get_db
from sleeper_service.runtime.outbound import (
    OutboundUrlError,
    notif_policy,
    validate_apprise_url,
)

router = APIRouter(prefix="/teams/{team_id}/notif-channels", tags=["notif-channels"])

VALID_EVENTS = {
    "dead_letter",
    "budget",
    "error_rate",
    "eval_regression",
    "callback_failed",
    "human_attention",
}


async def _gate(team_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal) -> Team:
    team = await db.get(Team, team_id)
    if team is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    require_role(principal, team_id, Role.OWNER)
    return team


@router.post("", response_model=NotifChannelOut, status_code=status.HTTP_201_CREATED)
async def create_channel(
    team_id: uuid.UUID,
    body: NotifChannelCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> NotifChannel:
    team = await _gate(team_id, db, principal)
    invalid = set(body.events) - VALID_EVENTS
    if invalid:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown events {sorted(invalid)}; valid: {sorted(VALID_EVENTS)}",
        )
    # The worker connects to whatever this URL names, so it is a server-side
    # outbound destination like a callback. Rejected here for fast feedback and
    # again at delivery, where the host is resolved.
    tenant = await db.get(Tenant, team.tenant_id)
    try:
        validate_apprise_url(body.apprise_url, tenant.settings if tenant else {}, **notif_policy())
    except OutboundUrlError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    channel = NotifChannel(
        team_id=team_id,
        apprise_url_enc=encrypt(body.apprise_url),
        events=body.events,
    )
    db.add(channel)
    await db.commit()
    await db.refresh(channel)
    return channel


@router.get("", response_model=list[NotifChannelOut])
async def list_channels(
    team_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[NotifChannel]:
    await _gate(team_id, db, principal)
    return list(await db.scalars(select(NotifChannel).where(NotifChannel.team_id == team_id)))


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    team_id: uuid.UUID,
    channel_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _gate(team_id, db, principal)
    channel = await db.get(NotifChannel, channel_id)
    if channel is None or channel.team_id != team_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(channel)
    await db.commit()
