from fastapi import APIRouter

from sleeper_service.api.v1 import agents, api_keys, teams, tenants, users

v1_router = APIRouter()
v1_router.include_router(tenants.router)
v1_router.include_router(users.router)
v1_router.include_router(teams.router)
v1_router.include_router(agents.router)
v1_router.include_router(api_keys.router)
