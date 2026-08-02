"""arq queue access for the API process."""

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from sleeper_service.config import get_settings

_pool: ArqRedis | None = None


async def get_pool() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    return _pool
