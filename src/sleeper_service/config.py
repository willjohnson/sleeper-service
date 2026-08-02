from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str
    # Local defaults match the docker-compose host port mappings (5433/6380,
    # offset to dodge natively installed Postgres/Redis instances).
    database_url: str = "postgresql+asyncpg://sleeper:sleeper@localhost:5433/sleeper"
    redis_url: str = "redis://localhost:6380/0"

    minio_endpoint: str = "http://localhost:9000"
    minio_access_key: str = "sleeper"
    minio_secret_key: str = "sleeper-minio-secret"
    minio_bucket: str = "sleeper-files"


@lru_cache
def get_settings() -> Settings:
    return Settings()
