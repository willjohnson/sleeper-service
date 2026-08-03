"""Toolsets granted to an agent version: MCP servers and data-store file tools.

MCP grants (BUILD_PLAN § Stack): `tool_grants` entries name a registered MCP
server and optionally allowlist tool names:
    {"server": "<name or id>", "tools": ["lookup", ...]}   # tools omitted = all
`user_ctx` rides along as an X-Sleeper-User-Ctx header on HTTP transports —
passthrough identity only; row-level enforcement is the data layer's job.

Data-store grants (BUILD_PLAN § Data stores): entries pin a store, a path
prefix, and a mode:
    {"store": "<name or id>", "prefix": "reports/2026", "mode": "ro"|"rw"}
exposed as list_files/read_file/write_file backed by fsspec (Box by its own
backend — see runtime/box_store.py), path-scoped to the granted prefix.
"""

import json
import posixpath
import uuid
from typing import Any

import anyio
import fsspec
from pydantic_ai import ModelRetry
from pydantic_ai.mcp import MCPToolset
from pydantic_ai.toolsets import AbstractToolset, FunctionToolset
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.crypto import decrypt
from sleeper_service.db.models import DataStore, McpServer

MAX_READ_BYTES = 200_000


class GrantError(Exception):
    """A grant references an unknown server/store or is malformed."""


# --- MCP ---


async def build_mcp_toolsets(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    tool_grants: list,
    user_ctx: dict | None,
) -> list[AbstractToolset]:
    toolsets: list[AbstractToolset] = []
    for grant in tool_grants:
        ref = grant.get("server", "")
        server = await _lookup(db, McpServer, tenant_id, ref)
        if server is None:
            raise GrantError(f"unknown MCP server in tool_grants: {ref!r}")

        headers: dict[str, str] = {}
        if server.credentials_enc:
            creds = json.loads(decrypt(server.credentials_enc))
            headers.update(creds.get("headers", {}))
        if user_ctx is not None:
            headers["X-Sleeper-User-Ctx"] = json.dumps(user_ctx)

        if server.transport == "stdio":
            import shlex

            from fastmcp.client.transports import StdioTransport

            command, *args = shlex.split(server.endpoint)
            toolset: AbstractToolset = MCPToolset(
                StdioTransport(command=command, args=args), id=f"mcp-{server.name}"
            )
        else:  # streamable_http | sse — FastMCP infers from the URL
            toolset = MCPToolset(server.endpoint, id=f"mcp-{server.name}", headers=headers or None)

        allowed = grant.get("tools")
        if allowed:
            allowed_set = set(allowed)
            toolset = toolset.filtered(lambda ctx, td, s=allowed_set: td.name in s)
        toolsets.append(toolset)
    return toolsets


# --- Data stores ---


class _StoreGrant:
    def __init__(self, store: DataStore, prefix: str, mode: str):
        self.store = store
        self.prefix = prefix.strip("/")
        self.mode = mode
        self._box = None  # memoized: construction does auth round trips

    def resolve(self, path: str) -> str:
        """Join and normalize path under the granted prefix; refuse escapes."""
        # Pure string checks only: relpath()/abspath() consult os.getcwd(),
        # which must never influence a permission boundary.
        candidate = posixpath.normpath(posixpath.join(self.prefix, path.lstrip("/")))
        escaped = candidate == ".." or candidate.startswith(("../", "/"))
        if self.prefix and candidate != self.prefix and not candidate.startswith(self.prefix + "/"):
            escaped = True
        if escaped:
            raise ModelRetry(f"path escapes the granted prefix: {path!r}")
        return candidate

    def fs_and_root(self) -> tuple[Any, str]:
        """Returns (filesystem, root): a real fsspec filesystem, or for Box a
        backend duck-typing the three calls the file tools make. Runs inside
        the tool's worker thread, so Box's auth round trips stay off the loop."""
        cfg = self.store.config or {}
        creds = (
            json.loads(decrypt(self.store.credentials_enc)) if self.store.credentials_enc else {}
        )
        if self.store.type == "s3":
            fs = fsspec.filesystem(
                "s3",
                key=creds.get("access_key"),
                secret=creds.get("secret_key"),
                endpoint_url=cfg.get("endpoint_url"),
            )
            return fs, cfg["bucket"]
        if self.store.type == "azure_blob":
            fs = fsspec.filesystem(
                "abfs",
                account_name=creds.get("account_name") or cfg.get("account_name"),
                account_key=creds.get("account_key"),
                connection_string=creds.get("connection_string"),
                sas_token=creds.get("sas_token"),
            )
            return fs, cfg["container"]
        if self.store.type == "gcs":
            # token: service-account info dict, a key-file path, or omitted to
            # fall back to application default credentials
            fs = fsspec.filesystem("gcs", token=creds.get("token"))
            return fs, cfg["bucket"]
        if self.store.type == "local":
            return fsspec.filesystem("file"), cfg["base_path"].rstrip("/")
        if self.store.type == "box":
            from sleeper_service.runtime.box_store import BoxBackend

            if self._box is None:
                self._box = BoxBackend(cfg, creds, self.mode)
            return self._box, BoxBackend.ROOT
        raise GrantError(f"data store type {self.store.type!r} not supported yet")


async def build_store_toolset(
    db: AsyncSession, tenant_id: uuid.UUID, data_store_grants: list
) -> AbstractToolset | None:
    if not data_store_grants:
        return None
    grants: dict[str, _StoreGrant] = {}
    for g in data_store_grants:
        ref = g.get("store", "")
        store = await _lookup(db, DataStore, tenant_id, ref)
        if store is None:
            raise GrantError(f"unknown data store in data_store_grants: {ref!r}")
        grants[store.name] = _StoreGrant(store, g.get("prefix", ""), g.get("mode", "ro"))

    def _grant(store_name: str) -> _StoreGrant:
        if store_name not in grants:
            raise ModelRetry(f"no grant for store {store_name!r}; granted: {sorted(grants)}")
        return grants[store_name]

    # fs_and_root() runs inside each thread: backend construction can do
    # real I/O (Box auth round trips, gcs token fetch) and must stay off
    # the event loop

    async def list_files(store_name: str, path: str = "") -> list[str]:
        """List files in a granted data store under the given path."""
        g = _grant(store_name)
        full = g.resolve(path)

        def _ls() -> list[str]:
            fs, root = g.fs_and_root()
            base = f"{root}/{full}" if full else root
            return [p.removeprefix(root + "/") for p in fs.ls(base, detail=False)]

        return await anyio.to_thread.run_sync(_ls)

    async def read_file(store_name: str, path: str) -> str:
        """Read a text file from a granted data store."""
        g = _grant(store_name)
        full = g.resolve(path)

        def _read() -> str:
            fs, root = g.fs_and_root()
            data = fs.cat_file(f"{root}/{full}")
            return data[:MAX_READ_BYTES].decode(errors="replace")

        return await anyio.to_thread.run_sync(_read)

    async def write_file(store_name: str, path: str, content: str) -> str:
        """Write a text file to a granted data store (requires a read-write grant)."""
        g = _grant(store_name)
        if g.mode != "rw":
            raise ModelRetry(f"store {store_name!r} is granted read-only")
        full = g.resolve(path)

        def _write() -> None:
            fs, root = g.fs_and_root()
            fs.pipe_file(f"{root}/{full}", content.encode())

        await anyio.to_thread.run_sync(_write)
        return f"wrote {len(content)} chars to {store_name}:{full}"

    return FunctionToolset([list_files, read_file, write_file], id="data-stores")


async def _lookup(db: AsyncSession, model: type, tenant_id: uuid.UUID, ref: str):
    try:
        return await db.get(model, uuid.UUID(str(ref)))
    except (ValueError, AttributeError):
        pass
    return await db.scalar(select(model).where(model.tenant_id == tenant_id, model.name == ref))
