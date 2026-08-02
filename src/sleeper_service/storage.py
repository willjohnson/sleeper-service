"""Object storage (MinIO / any S3-compatible endpoint) for payload files.

Uses fsspec/s3fs — the same stack data-store tools use — via its sync API in
worker threads.
"""

from functools import lru_cache

import anyio
import s3fs

from sleeper_service.config import get_settings


@lru_cache
def _fs() -> s3fs.S3FileSystem:
    s = get_settings()
    return s3fs.S3FileSystem(
        key=s.minio_access_key,
        secret=s.minio_secret_key,
        endpoint_url=s.minio_endpoint,
    )


def _ensure_bucket_sync() -> None:
    fs = _fs()
    bucket = get_settings().minio_bucket
    if not fs.exists(bucket):
        fs.mkdir(bucket)


async def ensure_bucket() -> None:
    await anyio.to_thread.run_sync(_ensure_bucket_sync)


async def put_object(key: str, data: bytes, content_type: str) -> None:
    def _put() -> None:
        _fs().pipe_file(
            f"{get_settings().minio_bucket}/{key}", data, ContentType=content_type
        )

    await anyio.to_thread.run_sync(_put)


async def get_object(key: str) -> bytes:
    def _get() -> bytes:
        return _fs().cat_file(f"{get_settings().minio_bucket}/{key}")

    return await anyio.to_thread.run_sync(_get)
