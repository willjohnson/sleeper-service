"""Request principals.

Every authenticated request resolves to exactly one principal:

- ``UserPrincipal`` — a user API key (management plane). Carries the user's
  team memberships; RBAC decisions come from those roles. Human sessions
  (Phase 4) will resolve to the same type.
- ``InvokePrincipal`` — an invoke key (data plane). Carries only its scope;
  it can submit jobs, read job results, and post feedback within that scope,
  and nothing else.
"""

import time
import uuid
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.auth.keys import hash_key
from sleeper_service.constants import KeyKind, KeyScope, Role
from sleeper_service.db.models import ApiKey, TeamMember, User
from sleeper_service.db.session import get_db
from sleeper_service.redis_client import get_redis


@dataclass
class UserPrincipal:
    user: User
    # team_id -> role for every team the user belongs to
    roles: dict[uuid.UUID, Role] = field(default_factory=dict)

    @property
    def is_superuser(self) -> bool:
        return self.user.is_superuser


@dataclass
class InvokePrincipal:
    key: ApiKey
    scope: KeyScope
    scope_id: uuid.UUID


Principal = UserPrincipal | InvokePrincipal

_credentials_error = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or missing API key",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _credentials_error

    key = await db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(token)))
    if key is None or key.revoked_at is not None:
        raise _credentials_error

    await _enforce_rate_limit(key)

    if key.kind == KeyKind.INVOKE:
        return InvokePrincipal(key=key, scope=KeyScope(key.scope), scope_id=key.scope_id)

    user = await db.get(User, key.user_id)
    if user is None:
        raise _credentials_error
    memberships = await db.scalars(select(TeamMember).where(TeamMember.user_id == user.id))
    roles = {m.team_id: Role(m.role) for m in memberships}
    return UserPrincipal(user=user, roles=roles)


async def _enforce_rate_limit(key: ApiKey) -> None:
    """Fixed-window (1 min) request limit for keys with rate_limit set."""
    if key.rate_limit is None:
        return
    window = int(time.time()) // 60
    redis_key = f"ratelimit:{key.id}:{window}"
    r = get_redis()
    count = await r.incr(redis_key)
    if count == 1:
        await r.expire(redis_key, 60)
    if count > key.rate_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for this API key",
            headers={"Retry-After": "60"},
        )


async def get_user_principal(
    principal: Principal = Depends(get_principal),
) -> UserPrincipal:
    """Management endpoints: invoke keys are never sufficient."""
    if not isinstance(principal, UserPrincipal):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires a user API key",
        )
    return principal
