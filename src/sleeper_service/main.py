import logging
import uuid as uuid_mod
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware

from sleeper_service import __version__, storage
from sleeper_service.api.v1.router import v1_router
from sleeper_service.config import get_settings
from sleeper_service.observability import setup_tracing

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

PLACEHOLDER_SECRETS = {"change-me", "changeme", "secret", ""}


@asynccontextmanager
async def lifespan(app: FastAPI):
    secret = get_settings().secret_key
    if secret.lower() in PLACEHOLDER_SECRETS or len(secret) < 16:
        logger.warning(
            "SECRET_KEY looks like a placeholder (callbacks, feedback tokens, and "
            "credential encryption are only as strong as this value) — set a real "
            "one in .env"
        )
    await storage.ensure_bucket()
    setup_tracing()
    yield


app = FastAPI(
    title="Sleeper Service",
    description="Agent as a Service — one agent, one task, a thousand of them.",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(v1_router, prefix="/v1")

from sleeper_service.ui.oidc import router as ui_oidc_router  # noqa: E402
from sleeper_service.ui.routes import NotAuthenticated  # noqa: E402
from sleeper_service.ui.routes import router as ui_router  # noqa: E402

app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().secret_key,
    same_site="lax",
    https_only=get_settings().session_https_only,
    max_age=get_settings().session_max_age_s,
)
app.include_router(ui_router)
app.include_router(ui_oidc_router)
app.mount(
    "/ui/static",
    StaticFiles(directory=str(Path(__file__).parent / "ui" / "static")),
    name="ui-static",
)


@app.exception_handler(NotAuthenticated)
async def _redirect_to_login(request: Request, exc: NotAuthenticated) -> RedirectResponse:
    return RedirectResponse("/ui/login", status_code=303)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    request_id = request.headers.get("X-Request-ID") or uuid_mod.uuid4().hex[:16]
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/healthz", include_in_schema=False)
async def healthz(response: Response) -> dict:
    """Readiness: verifies Postgres and Redis, not just process liveness."""
    from sleeper_service.db.session import get_sessionmaker
    from sleeper_service.redis_client import get_redis

    checks = {}
    try:
        async with get_sessionmaker()() as db:
            await db.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {type(e).__name__}"
    try:
        await get_redis().ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {type(e).__name__}"

    healthy = all(v == "ok" for v in checks.values())
    response.status_code = 200 if healthy else 503
    return {"status": "ok" if healthy else "degraded", "version": __version__, **checks}
