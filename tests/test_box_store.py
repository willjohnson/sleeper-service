"""Box data stores (BUILD_PLAN § Data stores): the file tools against a stub
Box API — a real uvicorn server in the test loop, because box-sdk-gen talks
real HTTP (token, downscope exchange, folders, download, upload).

What the stub proves beyond happy-path tools:
- CCG credentials are downscoped before any data call (data endpoints only
  accept the exchanged token, never the raw CCG one);
- read-only grants exchange for scopes without item_upload;
- the exchange resource pins the granted folder.
"""

import asyncio
import itertools
import json
import uuid

import pytest
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from httpx import AsyncClient
from pydantic_ai import ModelRetry

from sleeper_service.db.session import get_sessionmaker
from tests.conftest import auth

CCG_TOKEN = "raw-ccg-token"
SCOPED_PREFIX = "scoped::"


class StubBox:
    """In-memory folder tree: folders[fid] = {name: entry}, files[fid] = bytes."""

    def __init__(self, root_id: str):
        self.folders: dict[str, dict[str, dict]] = {root_id: {}}
        self.files: dict[str, bytes] = {}
        self.exchanges: list[dict] = []
        self._ids = itertools.count(2000)

    def add_folder(self, parent_id: str, name: str) -> str:
        fid = str(next(self._ids))
        self.folders[parent_id][name] = {"id": fid, "type": "folder", "name": name}
        self.folders[fid] = {}
        return fid

    def add_file(self, parent_id: str, name: str, data: bytes) -> str:
        fid = str(next(self._ids))
        self.folders[parent_id][name] = {"id": fid, "type": "file", "name": name}
        self.files[fid] = data
        return fid


def build_stub_app(box: StubBox) -> FastAPI:
    app = FastAPI()

    def _require_scoped(request: Request) -> None:
        header = request.headers.get("authorization", "")
        if not header.startswith(f"Bearer {SCOPED_PREFIX}"):
            raise HTTPException(401, f"data call without a downscoped token: {header!r}")

    @app.post("/oauth2/token")
    async def token(request: Request) -> dict:
        form = await request.form()
        if form.get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange":
            box.exchanges.append(
                {"scope": str(form.get("scope", "")), "resource": str(form.get("resource", ""))}
            )
            access = f"{SCOPED_PREFIX}{form.get('scope', '')}"
        else:
            access = CCG_TOKEN
        return {"access_token": access, "expires_in": 3600, "token_type": "bearer"}

    @app.get("/2.0/folders/{folder_id}/items")
    async def folder_items(folder_id: str, request: Request) -> dict:
        _require_scoped(request)
        if folder_id not in box.folders:
            raise HTTPException(404, "no such folder")
        entries = list(box.folders[folder_id].values())
        return {"total_count": len(entries), "entries": entries, "offset": 0, "limit": 1000}

    @app.post("/2.0/folders", status_code=201)
    async def create_folder(request: Request) -> dict:
        _require_scoped(request)
        body = await request.json()
        fid = box.add_folder(body["parent"]["id"], body["name"])
        return {"id": fid, "type": "folder", "name": body["name"]}

    @app.get("/2.0/files/{file_id}/content")
    async def download(file_id: str, request: Request) -> Response:
        _require_scoped(request)
        if file_id not in box.files:
            raise HTTPException(404, "no such file")
        return Response(content=box.files[file_id], media_type="application/octet-stream")

    @app.post("/upload-api/2.0/files/content", status_code=201)
    async def upload(request: Request) -> dict:
        _require_scoped(request)
        form = await request.form()
        attrs = json.loads(str(form["attributes"]))
        data = await form["file"].read()
        fid = box.add_file(attrs["parent"]["id"], attrs["name"], data)
        return {
            "total_count": 1,
            "entries": [{"id": fid, "type": "file", "name": attrs["name"]}],
        }

    @app.post("/upload-api/2.0/files/{file_id}/content", status_code=201)
    async def upload_version(file_id: str, request: Request) -> dict:
        _require_scoped(request)
        form = await request.form()
        if file_id not in box.files:
            raise HTTPException(404, "no such file")
        box.files[file_id] = await form["file"].read()
        name = json.loads(str(form["attributes"]))["name"]
        return {"total_count": 1, "entries": [{"id": file_id, "type": "file", "name": name}]}

    return app


ROOT_FOLDER = "1000"


@pytest.fixture
async def box_stub(unused_tcp_port: int) -> dict:
    box = StubBox(ROOT_FOLDER)
    box.add_file(ROOT_FOLDER, "notes.txt", b"threshold: 5%")
    reports = box.add_folder(ROOT_FOLDER, "reports")
    box.add_file(reports, "q1.txt", b"q1 data")

    server = uvicorn.Server(
        uvicorn.Config(
            build_stub_app(box), host="127.0.0.1", port=unused_tcp_port, log_level="warning"
        )
    )
    serve_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    yield {"box": box, "url": f"http://127.0.0.1:{unused_tcp_port}"}
    server.should_exit = True
    await serve_task


async def _register_and_build(client, root, tenant_id, url, grants):
    from sleeper_service.runtime.toolsets import build_store_toolset

    r = await client.post(
        f"/v1/tenants/{tenant_id}/data-stores",
        headers=root,
        json={
            "name": "boxstore",
            "type": "box",
            "config": {"folder_id": ROOT_FOLDER, "api_base_url": url, "max_retries": 1},
            "credentials": {
                "client_id": "cid",
                "client_secret": "csecret",
                "enterprise_id": "eid",
            },
        },
    )
    assert r.status_code in (201, 409), r.text
    async with get_sessionmaker()() as db:
        toolset = await build_store_toolset(db, uuid.UUID(tenant_id), grants)
    return {name: t.function for name, t in toolset.tools.items()}


async def test_box_store_tools(client: AsyncClient, org: dict, bootstrap, box_stub: dict) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    ro = await _register_and_build(
        client, root, tenant_id, box_stub["url"], [{"store": "boxstore", "mode": "ro"}]
    )

    listing = await ro["list_files"]("boxstore", "")
    assert sorted(listing) == ["notes.txt", "reports"]
    assert await ro["read_file"]("boxstore", "notes.txt") == "threshold: 5%"
    assert await ro["read_file"]("boxstore", "reports/q1.txt") == "q1 data"
    assert await ro["list_files"]("boxstore", "reports") == ["reports/q1.txt"]

    with pytest.raises(ModelRetry, match="read-only"):
        await ro["write_file"]("boxstore", "out.txt", "x")
    with pytest.raises(FileNotFoundError):
        await ro["read_file"]("boxstore", "missing.txt")

    # the read-only grant exchanged for scopes without upload rights,
    # pinned to the granted folder
    scopes = box_stub["box"].exchanges[0]["scope"]
    assert "item_download" in scopes and "item_upload" not in scopes
    assert box_stub["box"].exchanges[0]["resource"].endswith(f"/2.0/folders/{ROOT_FOLDER}")


async def test_box_store_rw_and_prefix(
    client: AsyncClient, org: dict, bootstrap, box_stub: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    rw = await _register_and_build(
        client,
        root,
        tenant_id,
        box_stub["url"],
        [{"store": "boxstore", "prefix": "reports", "mode": "rw"}],
    )

    # new file, existing-file overwrite (new version), and folder auto-create
    assert "wrote" in await rw["write_file"]("boxstore", "out.txt", "written")
    assert await rw["read_file"]("boxstore", "out.txt") == "written"
    await rw["write_file"]("boxstore", "q1.txt", "q1 v2")
    assert await rw["read_file"]("boxstore", "q1.txt") == "q1 v2"
    await rw["write_file"]("boxstore", "sub/deep.txt", "deep")
    assert await rw["read_file"]("boxstore", "sub/deep.txt") == "deep"

    # the grant prefix confines the agent inside reports/
    with pytest.raises(ModelRetry, match="escapes"):
        await rw["read_file"]("boxstore", "../notes.txt")

    # rw exchanged for upload scope
    assert any("item_upload" in e["scope"] for e in box_stub["box"].exchanges)


async def test_box_registration_requires_folder_id(
    client: AsyncClient, org: dict, bootstrap
) -> None:
    root = auth(bootstrap.superuser_key)
    r = await client.post(
        f"/v1/tenants/{org['tenant']['id']}/data-stores",
        headers=root,
        json={"name": "badbox", "type": "box", "config": {}},
    )
    assert r.status_code == 422
    assert "folder_id" in r.json()["detail"]


async def test_blob_gcs_registration_accepted(client: AsyncClient, org: dict, bootstrap) -> None:
    """Regression: the runtime gained azure_blob/gcs support before the
    registration API accepted them."""
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    for body in (
        {"name": "blob", "type": "azure_blob", "config": {"container": "c"}},
        {"name": "gcsstore", "type": "gcs", "config": {"bucket": "b"}},
    ):
        r = await client.post(f"/v1/tenants/{tenant_id}/data-stores", headers=root, json=body)
        assert r.status_code == 201, r.text
