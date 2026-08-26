from fastapi import APIRouter

from sleeper_service.api.v1 import (
    agents,
    api_keys,
    data_stores,
    evals,
    events,
    feedback,
    files,
    jobs,
    mcp_servers,
    memory_admin,
    models,
    notif_channels,
    oidc,
    provider_creds,
    teams,
    tenants,
    users,
    versions,
    work_items,
)

v1_router = APIRouter()
v1_router.include_router(tenants.router)
v1_router.include_router(oidc.router)
v1_router.include_router(users.router)
v1_router.include_router(teams.router)
v1_router.include_router(agents.router)
v1_router.include_router(versions.router)
v1_router.include_router(api_keys.router)
v1_router.include_router(models.router)
v1_router.include_router(provider_creds.router)
v1_router.include_router(files.router)
v1_router.include_router(jobs.router)
v1_router.include_router(mcp_servers.router)
v1_router.include_router(data_stores.router)
v1_router.include_router(notif_channels.router)
v1_router.include_router(events.router)
v1_router.include_router(feedback.router)
v1_router.include_router(evals.router)
v1_router.include_router(memory_admin.router)
v1_router.include_router(work_items.router)
