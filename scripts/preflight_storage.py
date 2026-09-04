"""Prove the configured object store works before deploying against it.

The API calls `ensure_bucket()` during startup, so unreachable or
under-permissioned storage does not degrade — it stops the service from
booting, behind whatever log noise the platform wraps it in. This runs the
same three calls the app does (`ensure_bucket`, `put_object`, `get_object`)
against whatever MINIO_* currently points at, and says which one failed.

Reads settings the way the app does, so a plain run checks the local compose
MinIO from .env. Override on the command line to check a remote endpoint —
environment variables outrank the dotenv file:

    MINIO_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com \
    MINIO_ACCESS_KEY=... MINIO_SECRET_KEY=... \
    MINIO_BUCKET=sleeper-files AWS_DEFAULT_REGION=auto \
    uv run python scripts/preflight_storage.py

Exits non-zero on the first failure.
"""

import asyncio
import os
import sys

from sleeper_service import storage
from sleeper_service.config import get_settings

KEY = "_preflight.txt"
BODY = b"hello from sleeper-service"


async def main() -> int:
    s = get_settings()
    print(f"endpoint : {s.minio_endpoint}")
    print(f"bucket   : {s.minio_bucket}")
    # Unset is a real failure mode rather than a cosmetic one: R2 has no
    # regions, but botocore refuses to sign a request without one.
    print(f"region   : {os.environ.get('AWS_DEFAULT_REGION', '(unset)')}")

    try:
        await storage.ensure_bucket()
    except Exception as e:
        print(f"\nFAILED reaching the bucket: {type(e).__name__}: {e}", file=sys.stderr)
        print(
            "\nA connection error usually means the endpoint is wrong — an S3 API "
            "endpoint, not a bucket's public dev URL. AccessDenied on a bucket that "
            "plainly exists means the credentials cannot HeadBucket it, so s3fs "
            "concludes it is missing and tries to create it; widen the token's scope.",
            file=sys.stderr,
        )
        return 1
    print("bucket   : reachable")

    try:
        await storage.put_object(KEY, BODY, "text/plain")
        got = await storage.get_object(KEY)
    except Exception as e:
        print(f"\nFAILED writing/reading an object: {type(e).__name__}: {e}", file=sys.stderr)
        print("The bucket exists but the credentials are not read-write on it.", file=sys.stderr)
        return 1
    if got != BODY:
        print(f"\nFAILED: read back {got!r}, expected {BODY!r}", file=sys.stderr)
        return 1
    print("round-trip: OK — put and read back")

    # Leave nothing behind; retention only sweeps rows it knows about.
    # _fs() is how runtime/retention.py deletes expired payloads too.
    storage._fs().rm_file(f"{s.minio_bucket}/{KEY}")
    print("cleanup  : removed the test object")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
