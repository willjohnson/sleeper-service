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

# Backends whose SDK falls back to the *host process's* ambient cloud identity
# when no credential is supplied: s3fs → botocore's chain (env, shared config,
# then the EC2/ECS/EKS instance role), gcsfs → application default credentials,
# adlfs → DefaultAzureCredential/managed identity. A credential-less store of
# these types therefore runs on the platform's own identity rather than the
# tenant's — the same confused-deputy shape as a `local` store pointing at the
# container filesystem, so it carries the same superuser-only gate. Operators
# who genuinely want an ADC-backed store still can; tenant admins cannot.
AMBIENT_CREDENTIAL_TYPES = {"s3", "azure_blob", "gcs"}


@router.post("", response_model=DataStoreOut, status_code=status.HTTP_201_CREATED)
async def create_data_store(
    tenant_id: uuid.UUID,
    body: DataStoreCreate,
    db: AsyncSession = Depends(get_db),
    principal: UserPrincipal = Depends(get_user_principal),
) -> DataStore:
    await _gate(tenant_id, db, principal, admin=True)
    if body.type == "local" and not principal.is_superuser:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only instance superusers may register local data stores",
        )
    if (
        body.type in AMBIENT_CREDENTIAL_TYPES
        and not body.credentials
        and not principal.is_superuser
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"{body.type} data stores require explicit credentials; without them the store "
            "runs on the platform's own cloud identity, which only instance superusers "
            "may configure",
        )
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
