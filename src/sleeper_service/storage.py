"""Object storage (MinIO / any S3-compatible endpoint) for payload files."""

from functools import lru_cache

import anyio
import boto3

from sleeper_service.config import get_settings


@lru_cache
def _client():
    s = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=s.minio_endpoint,
        aws_access_key_id=s.minio_access_key,
        aws_secret_access_key=s.minio_secret_key,
        region_name="us-east-1",
    )


def _ensure_bucket_sync() -> None:
    client = _client()
    bucket = get_settings().minio_bucket
    try:
        client.head_bucket(Bucket=bucket)
    except client.exceptions.ClientError:
        client.create_bucket(Bucket=bucket)


async def ensure_bucket() -> None:
    await anyio.to_thread.run_sync(_ensure_bucket_sync)


async def put_object(key: str, data: bytes, content_type: str) -> None:
    def _put() -> None:
        _client().put_object(
            Bucket=get_settings().minio_bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
        )

    await anyio.to_thread.run_sync(_put)


async def get_object(key: str) -> bytes:
    def _get() -> bytes:
        resp = _client().get_object(Bucket=get_settings().minio_bucket, Key=key)
        return resp["Body"].read()

    return await anyio.to_thread.run_sync(_get)
