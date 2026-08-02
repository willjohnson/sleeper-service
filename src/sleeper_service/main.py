from fastapi import FastAPI

from sleeper_service import __version__
from sleeper_service.api.v1.router import v1_router

app = FastAPI(
    title="Sleeper Service",
    description="Agent as a Service — one agent, one task, a thousand of them.",
    version=__version__,
)

app.include_router(v1_router, prefix="/v1")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
