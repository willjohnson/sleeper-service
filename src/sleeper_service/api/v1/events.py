"""Event sources: webhook ingress that turns external events into jobs
(BUILD_PLAN § Event sources).

Management is by the owner of the target agent's team. Ingress authenticates
with the per-source secret alone (X-Event-Secret header) — external pollers
and senders never hold platform API keys. Dedup: `dedup_key_path` extracts a
key from the event body; duplicates map onto the jobs idempotency constraint
and return the original job with deduped=true.
"""

import hmac
import re
import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.jobs import _resolve_version_current, create_job
from sleeper_service.api.v1.schemas import (
    EventAccepted,
    EventSourceCreate,
    EventSourceOut,
    EventSourceWithSecretOut,
    JobContext,
)
from sleeper_service.auth.keys import hash_key
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.auth.rbac import require_role
from sleeper_service.constants import Role
from sleeper_service.db.models import Agent, EventSource, File, Tenant
from sleeper_service.db.session import get_db
from sleeper_service.runtime import links as links_mod

router = APIRouter(tags=["events"])

_TEMPLATE_VAR = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _dig(body: Any, path: str) -> Any:
    value = body
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def render_template(template: dict, body: dict) -> dict:
    """Substitute {{path.to.field}} in template string values; {{body}} is the
    whole event body as JSON."""
    import json

    def render_value(value: Any) -> Any:
        if isinstance(value, str):

            def sub(m: re.Match) -> str:
                path = m.group(1)
                if path == "body":
                    return json.dumps(body)
                found = _dig(body, path)
                return "" if found is None else str(found)

            return _TEMPLATE_VAR.sub(sub, value)
        if isinstance(value, dict):
            return {k: render_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [render_value(v) for v in value]
        return value

    return render_value(template)


# --- Management ---


@router.post(
    "/tenants/{tenant_id}/event-sources",
    response_model=EventSourceWithSecretOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_event_source(
    tenant_id: uuid.UUID,
    body: EventSourceCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> EventSourceWithSecretOut:
    if await db.get(Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    agent = await db.get(Agent, body.target_agent_id)
    if agent is None or agent.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown target agent")
    require_role(principal, agent.team_id, Role.OWNER)
    dup = await db.scalar(
        select(EventSource).where(EventSource.tenant_id == tenant_id, EventSource.name == body.name)
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "Event source name already exists")

    secret = "ss_evt_" + secrets.token_urlsafe(24)
    source = EventSource(
        tenant_id=tenant_id,
        name=body.name,
        target_agent_id=body.target_agent_id,
        payload_template=body.payload_template,
        dedup_key_path=body.dedup_key_path,
        secret_hash=hash_key(secret),
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return EventSourceWithSecretOut(
        **{f: getattr(source, f) for f in EventSourceOut.model_fields}, secret=secret
    )


@router.get("/tenants/{tenant_id}/event-sources", response_model=list[EventSourceOut])
async def list_event_sources(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[EventSource]:
    sources = list(await db.scalars(select(EventSource).where(EventSource.tenant_id == tenant_id)))
    visible = []
    for source in sources:
        agent = await db.get(Agent, source.target_agent_id)
        if agent and (principal.is_superuser or agent.team_id in principal.roles):
            visible.append(source)
    return visible


@router.delete(
    "/tenants/{tenant_id}/event-sources/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_event_source(
    tenant_id: uuid.UUID,
    source_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    source = await db.get(EventSource, source_id)
    if source is None or source.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    agent = await db.get(Agent, source.target_agent_id)
    if agent is not None:
        require_role(principal, agent.team_id, Role.OWNER)
    else:
        from sleeper_service.auth.rbac import require_tenant_admin

        await require_tenant_admin(db, principal, tenant_id)
    await db.delete(source)
    await db.commit()


# --- Ingress (secret-authenticated; no platform key) ---


@router.post(
    "/events/{source_id}",
    response_model=EventAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_event(
    source_id: uuid.UUID,
    body: dict,
    x_event_secret: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
) -> EventAccepted:
    source = await db.get(EventSource, source_id)
    if (
        source is None
        or not x_event_secret
        or not hmac.compare_digest(hash_key(x_event_secret), source.secret_hash)
    ):
        # One error for both unknown source and bad secret — don't leak which
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid event source or secret")

    agent = await db.get(Agent, source.target_agent_id)
    version = await _resolve_version_current(db, agent)

    rendered = render_template(source.payload_template, body)
    try:
        context = JobContext.model_validate(rendered)
    except ValidationError as e:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"payload_template produced an invalid job context: {e.error_count()} errors",
        ) from e

    if context.links:
        tenant = await db.get(Tenant, agent.tenant_id)
        link_error = links_mod.check_links(context.links, tenant.settings or {})
        if link_error is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, link_error)

    for file_id in context.files:
        file = await db.get(File, file_id)
        if file is None or file.tenant_id != agent.tenant_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown file {file_id}")

    idempotency_key = None
    if source.dedup_key_path:
        dedup_value = _dig(body, source.dedup_key_path)
        if dedup_value is not None:
            idempotency_key = f"evt:{source.id}:{dedup_value}"

    job, existed = await create_job(
        db,
        agent,
        version,
        context=context.model_dump(mode="json"),
        auth_ctx={
            "type": "event_source",
            "source_id": str(source.id),
            "tenant_id": str(source.tenant_id),
        },
        idempotency_key=idempotency_key,
    )
    return EventAccepted(job_id=job.id, deduped=existed)
