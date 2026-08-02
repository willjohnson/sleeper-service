"""Models registry: which provider model strings agent versions may reference.

Superusers manage the registry (instance-level, shared across tenants); any
authenticated user key can read it.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import ModelCreate, ModelOut
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.db.models import Model
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/models", tags=["models"])


@router.post("", response_model=ModelOut, status_code=status.HTTP_201_CREATED)
async def create_model(
    body: ModelCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> Model:
    if not principal.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only superusers manage models")
    dup = await db.scalar(
        select(Model).where(Model.provider == body.provider, Model.name == body.name)
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "Model already registered")
    model = Model(provider=body.provider, name=body.name, model_string=body.model_string)
    db.add(model)
    await db.commit()
    await db.refresh(model)
    return model


@router.get("", response_model=list[ModelOut])
async def list_models(
    db: AsyncSession = Depends(get_db),
    _: UserPrincipal = Depends(get_user_principal),
) -> list[Model]:
    return list(await db.scalars(select(Model).order_by(Model.provider, Model.name)))


@router.delete("/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_model(
    model_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    if not principal.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only superusers manage models")
    model = await db.get(Model, model_id)
    if model is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(model)
    await db.commit()
