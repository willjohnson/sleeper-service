"""Box data stores (BUILD_PLAN § Data stores).

Box addresses items by ID, not path, so the granted root is a folder ID and
paths resolve by walking item *names* down from that root — the file tools
never accept Box IDs, which means an agent has no way to address anything
outside the granted subtree. Layered under that, CCG credentials are
downscoped (token exchange restricted to the granted folder, read-only
scopes unless the grant is rw) before any data call, so the token in use
can't reach outside the subtree either.

Backed by the official box-sdk-gen (sync/requests) and duck-typing the three
fsspec calls the file tools make — ls / cat_file / pipe_file — so toolsets
treats Box like any other store, off the event loop via anyio.to_thread.
`config.api_base_url` overrides the Box endpoints for tests or gateways.
"""

import io
from collections.abc import Iterator
from typing import Any

from box_sdk_gen import (
    BaseUrls,
    BoxCCGAuth,
    BoxClient,
    BoxDeveloperTokenAuth,
    CCGConfig,
    NetworkSession,
)
from box_sdk_gen.managers.folders import CreateFolderParent
from box_sdk_gen.managers.uploads import (
    UploadFileAttributes,
    UploadFileAttributesParentField,
    UploadFileVersionAttributes,
)
from box_sdk_gen.networking.retries import BoxRetryStrategy

READ_SCOPES = ["base_explorer", "item_download"]
WRITE_SCOPES = [*READ_SCOPES, "item_upload"]


def _item_type(item: Any) -> str:
    return str(getattr(item.type, "value", item.type))


class BoxBackend:
    """One granted Box subtree, rooted at ``config["folder_id"]``.

    Paths handed to ls/cat_file/pipe_file carry the constant ROOT prefix
    (toolsets composes "{root}/{path}" for every store type).
    """

    ROOT = "box"

    def __init__(self, config: dict, creds: dict, mode: str):
        self._folder_id = str(config["folder_id"])
        api = (config.get("api_base_url") or "").rstrip("/")
        retry = BoxRetryStrategy(max_attempts=int(config.get("max_retries", 5)))
        session = (
            NetworkSession(
                retry_strategy=retry,
                base_urls=BaseUrls(
                    base_url=api, upload_url=f"{api}/upload-api", oauth_2_url=f"{api}/oauth2"
                ),
            )
            if api
            else NetworkSession(retry_strategy=retry)
        )
        if creds.get("developer_token"):
            # dev/test path: a raw token is used as-is (no exchange available)
            token = creds["developer_token"]
        else:
            auth = BoxCCGAuth(
                CCGConfig(
                    creds["client_id"],
                    creds["client_secret"],
                    enterprise_id=creds.get("enterprise_id"),
                    user_id=creds.get("user_id"),
                )
            )
            resource = f"{api or 'https://api.box.com'}/2.0/folders/{self._folder_id}"
            token = auth.downscope_token(
                WRITE_SCOPES if mode == "rw" else READ_SCOPES,
                resource=resource,
                network_session=session,
            ).access_token
        self._client = BoxClient(auth=BoxDeveloperTokenAuth(token), network_session=session)

    # --- name-walk resolution ---

    def _items(self, folder_id: str) -> Iterator[Any]:
        offset = 0
        while True:
            page = self._client.folders.get_folder_items(folder_id, offset=offset, limit=1000)
            yield from page.entries
            offset += len(page.entries)
            if not page.entries or offset >= (page.total_count or 0):
                return

    def _child(self, folder_id: str, name: str) -> Any | None:
        return next((i for i in self._items(folder_id) if i.name == name), None)

    def _resolve_folder(self, parts: list[str], create: bool = False) -> str:
        folder_id = self._folder_id
        for depth, name in enumerate(parts):
            item = self._child(folder_id, name)
            if item is None:
                if not create:
                    raise FileNotFoundError(f"no such folder: {'/'.join(parts[: depth + 1])}")
                item = self._client.folders.create_folder(name, CreateFolderParent(id=folder_id))
            elif _item_type(item) != "folder":
                raise NotADirectoryError(f"not a folder: {'/'.join(parts[: depth + 1])}")
            folder_id = item.id
        return folder_id

    def _parts(self, path: str) -> list[str]:
        # "." appears when grant prefix and path are both empty (normpath("")):
        # harmless to fsspec backends, meaningless to a name walk
        rel = path.removeprefix(self.ROOT).strip("/")
        return [p for p in rel.split("/") if p and p != "."]

    # --- the fsspec-shaped surface toolsets uses ---

    def ls(self, path: str, detail: bool = False) -> list[str]:
        parts = self._parts(path)
        folder_id = self._resolve_folder(parts)
        prefix = "/".join([self.ROOT, *parts])
        return [f"{prefix}/{item.name}" for item in self._items(folder_id)]

    def cat_file(self, path: str) -> bytes:
        *parents, name = self._parts(path)
        item = self._child(self._resolve_folder(parents), name)
        if item is None or _item_type(item) != "file":
            raise FileNotFoundError(f"no such file: {'/'.join([*parents, name])}")
        return self._client.downloads.download_file(item.id).read()

    def pipe_file(self, path: str, data: bytes) -> None:
        *parents, name = self._parts(path)
        folder_id = self._resolve_folder(parents, create=True)
        existing = self._child(folder_id, name)
        if existing is None:
            attributes = UploadFileAttributes(
                name=name, parent=UploadFileAttributesParentField(id=folder_id)
            )
            self._client.uploads.upload_file(attributes, io.BytesIO(data))
        else:
            self._client.uploads.upload_file_version(
                existing.id, UploadFileVersionAttributes(name=name), io.BytesIO(data)
            )
