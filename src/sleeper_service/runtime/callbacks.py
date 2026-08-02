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


def sign(body: bytes, timestamp: int) -> str:
    mac = hmac.new(
        get_settings().secret_key.encode(),
        f"{timestamp}.".encode() + body,
        hashlib.sha256,
    )
    return f"t={timestamp},v1={mac.hexdigest()}"


def build_payload(job: Job) -> dict:
    return {
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


class CallbackDeliveryError(Exception):
    """Non-2xx or network failure: worth retrying with backoff."""


async def deliver(job_id: uuid.UUID) -> None:
    async with get_sessionmaker()() as db:
        job = await db.get(Job, job_id)
        if job is None or not job.callback_url:
            return
        body = json.dumps(build_payload(job)).encode()
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
