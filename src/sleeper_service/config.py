from functools import lru_cache
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str
    database_url: str = "postgresql+asyncpg://sleeper:sleeper@localhost:5432/sleeper"
    redis_url: str = "redis://localhost:6379/0"

    minio_endpoint: str = "http://localhost:9000"
    # Required, with no default on purpose. BYO s3 endpoints are an intended
    # feature, so a tenant admin may point a data store at any endpoint the
    # worker can reach — including the platform's own object store. A shipped
    # default would be public knowledge and would turn that feature into a
    # cross-tenant read of the payload bucket, so there is no value to leave
    # unrotated. Compose passes the same pair to the minio container.
    minio_access_key: str
    minio_secret_key: str
    minio_bucket: str = "sleeper-files"

    # Job execution
    job_max_tries: int = 4  # arq attempts before dead-letter
    callback_max_tries: int = 5
    sync_job_timeout_s: int = 120  # cap for ?sync=true regardless of version timeout

    # How often the worker asks Redis for queued work. arq has no push wakeup,
    # so this is both the worst-case delay before an async job is picked up and
    # the worker's entire idle Redis traffic — one ZRANGEBYSCORE per tick,
    # about 5.2M commands a month at 0.5s. That is free against a Redis you
    # host and a real line item against a per-command managed one, so small
    # deployments can trade pickup latency for cost by raising it. `?sync=true`
    # never touches the queue, so its latency is unaffected either way.
    # Deferred work (callback delivery, the hourly retention cron) fires within
    # one tick of its due time, so keep this well under a minute.
    worker_poll_delay_s: float = 1.0

    # Cap on request bodies. FastAPI buffers the whole body into memory
    # before content-type inspection or auth, so this bounds request memory
    # for every endpoint; multipart uploads are exempt (streamed to disk, and
    # the files route enforces MAX_FILE_SIZE on the rolled size).
    request_body_max_bytes: int = 1_048_576

    # Browser authentication. Production defaults are secure; local HTTP
    # development and tests must explicitly disable the Secure cookie flag.
    session_https_only: bool = True
    session_max_age_s: int = 28_800
    login_rate_limit: int = 10
    login_rate_window_s: int = 300

    # Number of trusted reverse proxies in front of the app. 0 (the default)
    # means the app is reached directly, so X-Forwarded-For is ignored — a
    # client can set that header freely, and honouring it unconditionally
    # would let anyone sidestep the login rate limit by varying it per
    # request. Set it to the real hop count only when every one of those hops
    # is under your control. Leave it at 0 if you instead run uvicorn with
    # --proxy-headers, which rewrites the peer address before the app sees it.
    trusted_proxy_hops: int = 0

    # OIDC issuer validation. Production rejects loopback/private issuers; the
    # e2e stub IdP runs on 127.0.0.1, so tests enable this hatch explicitly.
    oidc_allow_loopback_issuers: bool = False

    # Total wall-clock budget for one prompt-injection heuristic pass, shared
    # across every pattern and every piece of untrusted content in it. Tenants
    # supply their own patterns, so the pass needs a ceiling that does not
    # scale with how many they add. Generous by default because a job may
    # inline a large text file; lower it if screening latency matters more
    # than scanning big attachments.
    injection_screen_timeout_s: float = 5.0

    # Alert destinations (BUILD_PLAN § Notifications & alerting). Team owners
    # supply Apprise URLs, which the worker then connects to, so the permitted
    # schemes are a platform decision rather than a tenant one. Extra schemes
    # are always host-validated, so widening the set cannot skip the address
    # check. Allow private hosts only where the alert server shares the
    # worker's private network — it removes the internal-reachability check.
    notif_extra_schemes: str = ""
    notif_allow_private_hosts: bool = False

    # MCP server endpoints are fetched by the worker on every job that grants
    # the server, so non-public addresses are refused by default. Allow them
    # only where the MCP servers share a private network with the worker (the
    # compose mcp-* sidecar shape) — the same trade NOTIF_ALLOW_PRIVATE_HOSTS
    # makes for self-hosted alert servers.
    mcp_allow_private_hosts: bool = False

    # Delegation / memory / learning
    max_delegation_depth: int = 3
    memory_max_chars: int = 6000
    public_base_url: str = "http://localhost:8000"  # used in feedback URLs

    # Sandboxed code runners (BUILD_PLAN § Runner design): comma-separated
    # enabled backends, first is the default. "docker" needs the Docker
    # socket mounted into api and worker.
    runner_backends: str = "monty"
    runner_docker_image: str = "python:3.12-slim"

    # Langfuse tracing (optional; enabled when all three are set)
    langfuse_host: str | None = None  # e.g. http://langfuse-web:3000
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None

    @field_validator("database_url")
    @classmethod
    def _asyncpg_url(cls, v: str) -> str:
        """Accept the libpq-shaped URLs managed Postgres providers hand out.

        Render, Neon and RDS all emit `postgresql://...` (or the legacy
        `postgres://`), frequently carrying libpq's `sslmode` query parameter.
        This app is async end to end, and SQLAlchemy's asyncpg dialect forwards
        query arguments untouched to `asyncpg.connect()`, which understands
        `ssl` but not `sslmode`. Rewriting here covers both the app engine and
        alembic, since each reads this one setting.
        """
        parts = urlsplit(v)
        if parts.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
            return v
        query = [
            ("ssl", value) if key == "sslmode" else (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit(
            ("postgresql+asyncpg", parts.netloc, parts.path, urlencode(query), parts.fragment)
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
