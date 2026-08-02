import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import (
    ApiKeyWithSecretOut,
    MeOut,
    UserCreate,
    UserWithKeyOut,
)
from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.passwords import hash_password
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.constants import KeyKind
from sleeper_service.db.models import ApiKey, User
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserWithKeyOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> UserWithKeyOut:
    if not principal.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only superusers create users")
    if await db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        is_superuser=body.is_superuser,
    )
    db.add(user)
    await db.flush()
    plaintext, key_hash = generate_key(KeyKind.USER)
    db.add(ApiKey(kind=KeyKind.USER, user_id=user.id, key_hash=key_hash, name="initial"))
    await db.commit()
    await db.refresh(user)
    return UserWithKeyOut(**user.__dict__, api_key=plaintext)


@router.get("/me", response_model=MeOut)
async def me(principal: UserPrincipal = Depends(get_user_principal)) -> MeOut:
    return MeOut(**principal.user.__dict__, roles=principal.roles)


@router.post(
    "/{user_id}/keys",
    response_model=ApiKeyWithSecretOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_key(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> ApiKeyWithSecretOut:
    if user_id != principal.user.id and not principal.is_superuser:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if await db.get(User, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    plaintext, key_hash = generate_key(KeyKind.USER)
    key = ApiKey(kind=KeyKind.USER, user_id=user_id, key_hash=key_hash)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return ApiKeyWithSecretOut(**_key_dict(key), api_key=plaintext)


@router.delete("/{user_id}/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_user_key(
    user_id: uuid.UUID,
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    if user_id != principal.user.id and not principal.is_superuser:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    key = await db.get(ApiKey, key_id)
    if key is None or key.user_id != user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
        await db.commit()


def _key_dict(key: ApiKey) -> dict:
    return {
        c: getattr(key, c)
        for c in (
            "id",
            "kind",
            "user_id",
            "scope",
            "scope_id",
            "name",
            "rate_limit",
            "created_at",
            "revoked_at",
        )
    }
