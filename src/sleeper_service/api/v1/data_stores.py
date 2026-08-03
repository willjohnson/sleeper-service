"""Data store registry (BUILD_PLAN § Data stores): tenant admin manages;
agent versions get path-scoped grants in data_store_grants."""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.mcp_servers import _gate
from sleeper_service.api.v1.schemas import DataStoreCreate, DataStoreOut
from sleeper_service.auth.principal import UserPrincipal, get_user_principal
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import DataStore
from sleeper_service.db.session import get_db

router = APIRouter(prefix="/tenants/{tenant_id}/data-stores", tags=["data-stores"])

REQUIRED_CONFIG = {
    "s3": "bucket",
    "azure_blob": "container",
    "gcs": "bucket",
    "box": "folder_id",
    "local": "base_path",
}


@router.post("", response_model=DataStoreOut, status_code=status.HTTP_201_CREATED)
async def create_data_store(
    tenant_id: uuid.UUID,
    body: DataStoreCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> DataStore:
    await _gate(tenant_id, db, principal, admin=True)
    if body.type not in REQUIRED_CONFIG:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"data store type {body.type!r} not supported; one of {sorted(REQUIRED_CONFIG)}",
        )
    required = REQUIRED_CONFIG[body.type]
    if required not in body.config:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"config requires {required!r}")
    dup = await db.scalar(
        select(DataStore).where(DataStore.tenant_id == tenant_id, DataStore.name == body.name)
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "Data store name already exists")
    store = DataStore(
        tenant_id=tenant_id,
        name=body.name,
        type=body.type,
        config=body.config,
        credentials_enc=encrypt(json.dumps(body.credentials)) if body.credentials else None,
    )
    db.add(store)
    await db.commit()
    await db.refresh(store)
    return store


@router.get("", response_model=list[DataStoreOut])
async def list_data_stores(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> list[DataStore]:
    await _gate(tenant_id, db, principal, admin=False)
    return list(
        await db.scalars(
            select(DataStore).where(DataStore.tenant_id == tenant_id).order_by(DataStore.name)
        )
    )


@router.delete("/{store_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_data_store(
    tenant_id: uuid.UUID,
    store_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> None:
    await _gate(tenant_id, db, principal, admin=True)
    store = await db.get(DataStore, store_id)
    if store is None or store.tenant_id != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    await db.delete(store)
    await db.commit()
