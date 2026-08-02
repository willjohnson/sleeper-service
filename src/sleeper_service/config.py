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

    # Job execution
    job_max_tries: int = 4  # arq attempts before dead-letter
    callback_max_tries: int = 5
    sync_job_timeout_s: int = 120  # cap for ?sync=true regardless of version timeout

    # Delegation / memory / learning
    max_delegation_depth: int = 3
    memory_max_chars: int = 6000
    public_base_url: str = "http://localhost:8000"  # used in feedback URLs

    # Langfuse tracing (optional; enabled when all three are set)
    langfuse_host: str | None = None  # e.g. http://langfuse-web:3000
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
