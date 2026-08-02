"""arq worker entrypoint. Job execution functions arrive in Phase 1."""

from typing import ClassVar

from arq.connections import RedisSettings

from sleeper_service.config import get_settings


async def ping(ctx: dict) -> str:
    return "pong"


class WorkerSettings:
    functions: ClassVar = [ping]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
