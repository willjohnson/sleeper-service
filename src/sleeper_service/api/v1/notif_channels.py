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
from sleeper_service.db.models import NotifChannel, Team
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/teams/{team_id}/notif-channels", tags=["notif-channels"])

VALID_EVENTS = {"dead_letter", "budget", "error_rate"}


async def _gate(team_id: uuid.UUID, db: AsyncSession, principal: UserPrincipal) -> None:
    if await db.get(Team, team_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    require_role(principal, team_id, Role.OWNER)


@router.post("", response_model=NotifChannelOut, status_code=status.HTTP_201_CREATED)
async def create_channel(
    team_id: uuid.UUID,
    body: NotifChannelCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> NotifChannel:
    await _gate(team_id, db, principal)
    invalid = set(body.events) - VALID_EVENTS
    if invalid:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown events {sorted(invalid)}; valid: {sorted(VALID_EVENTS)}",
        )
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
