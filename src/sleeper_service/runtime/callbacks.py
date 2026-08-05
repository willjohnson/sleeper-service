"""HMAC-signed webhook callbacks (BUILD_PLAN § Job lifecycle / Security).

Receivers verify with their shared SECRET_KEY:
    signed = f"{timestamp}.{raw_body}"
    expected = HMAC-SHA256(SECRET_KEY, signed)
Header: X-Sleeper-Signature: t=<unix ts>,v1=<hex digest>
"""

import hashlib
import hmac
import json
import time
import uuid

import httpx

from sleeper_service.config import get_settings
from sleeper_service.db.models import Job, JobEvent
from sleeper_service.db.session import get_sessionmaker
from sleeper_service.runtime.outbound import OutboundUrlError, validate_callback_target


def sign(body: bytes, timestamp: int) -> str:
    mac = hmac.new(
        get_settings().secret_key.encode(),
        f"{timestamp}.".encode() + body,
        hashlib.sha256,
    )
    return f"t={timestamp},v1={mac.hexdigest()}"


def build_payload(job: Job, *, learning: bool = False) -> dict:
    payload = {
        "job_id": str(job.id),
        "agent_id": str(job.agent_id),
        "agent_version_id": str(job.agent_version_id),
        "status": job.status,
        "output": job.output,
        "error": job.error,
        "tokens_in": job.tokens_in,
        "tokens_out": job.tokens_out,
        "cost": str(job.cost),
    }
    if learning:
        from sleeper_service.runtime.learning import feedback_url

        payload["feedback_url"] = feedback_url(job.id)
    return payload


class CallbackDeliveryError(Exception):
    """Non-2xx or network failure: worth retrying with backoff."""


class CallbackDestinationRejected(CallbackDeliveryError):
    """Outbound policy refused the destination: retrying cannot help.

    The callback URL is fixed on the job and the policy will not change
    within a retry window, so the remaining attempts would re-resolve the same
    name and reject it again — burning the backoff schedule and delaying the
    operator's alert for no reason. Fail once, and say why.
    """


async def deliver(job_id: uuid.UUID) -> None:
    async with get_sessionmaker()() as db:
        job = await db.get(Job, job_id)
        if job is None or not job.callback_url:
            return
        from sleeper_service.db.models import Agent, Tenant
        from sleeper_service.runtime.memory import learning_enabled

        agent = await db.get(Agent, job.agent_id)
        tenant = await db.get(Tenant, agent.tenant_id) if agent is not None else None
        if tenant is None:
            raise CallbackDeliveryError("callback job has no tenant")
        try:
            await validate_callback_target(job.callback_url, tenant.settings or {})
        except OutboundUrlError as e:
            raise CallbackDestinationRejected(f"callback destination rejected: {e}") from e
        learning = agent is not None and learning_enabled(agent.options or {})
        body = json.dumps(build_payload(job, learning=learning)).encode()
        signature = sign(body, int(time.time()))
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    job.callback_url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Sleeper-Signature": signature,
                    },
                )
        except httpx.HTTPError as e:
            raise CallbackDeliveryError(str(e)) from e
        if resp.status_code >= 300:
            raise CallbackDeliveryError(f"callback returned {resp.status_code}")
        db.add(
            JobEvent(job_id=job.id, type="callback_delivered", data={"status": resp.status_code})
        )
        await db.commit()


async def record_callback_failure(job_id: uuid.UUID, message: str) -> None:
    async with get_sessionmaker()() as db:
        db.add(JobEvent(job_id=job_id, type="callback_failed", data={"error": message}))
        await db.commit()
