"""arq queue access for the API process.

Jobs are serialized as JSON, not arq's default pickle. Every enqueued
argument here is a plain UUID string, so JSON loses nothing — and it keeps
`pickle.loads` off the path that deserializes whatever is sitting in Redis,
so reaching the queue is not the same as executing code in the worker.
Both ends must agree: see `WorkerSettings` in worker.py.
"""

import json
from typing import Any

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from sleeper_service.config import get_settings

_pool: ArqRedis | None = None


def job_serializer(data: dict[str, Any]) -> bytes:
    # default=str so a non-JSON-native result (datetime, Decimal) degrades to
    # a string instead of failing the job's result write.
    return json.dumps(data, default=str).encode()


def job_deserializer(raw: bytes) -> dict[str, Any]:
    return json.loads(raw)


async def get_pool() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(
            RedisSettings.from_dsn(get_settings().redis_url),
            job_serializer=job_serializer,
            job_deserializer=job_deserializer,
        )
    return _pool
