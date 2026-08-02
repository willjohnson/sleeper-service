from contextlib import asynccontextmanager

from fastapi import FastAPI

from sleeper_service import __version__, storage
from sleeper_service.api.v1.router import v1_router
from sleeper_service.observability import setup_tracing


@asynccontextmanager
async def lifespan(app: FastAPI):
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


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
