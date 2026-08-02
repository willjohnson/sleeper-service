from httpx import AsyncClient

from tests.conftest import Bootstrap, auth


async def test_healthz_needs_no_auth(client: AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_missing_key_is_401(client: AsyncClient) -> None:
    r = await client.get("/v1/tenants")
    assert r.status_code == 401


async def test_garbage_key_is_401(client: AsyncClient) -> None:
    r = await client.get("/v1/tenants", headers=auth("ss_user_not-a-real-key"))
    assert r.status_code == 401


async def test_bootstrap_key_works(client: AsyncClient, bootstrap: Bootstrap) -> None:
    r = await client.get("/v1/users/me", headers=auth(bootstrap.superuser_key))
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "root@example.com"
    assert body["is_superuser"] is True


async def test_revoked_key_is_401(client: AsyncClient, bootstrap: Bootstrap) -> None:
    key = bootstrap.superuser_key
    r = await client.post(f"/v1/users/{bootstrap.superuser_id}/keys", headers=auth(key))
    assert r.status_code == 201
    new_key = r.json()
    r = await client.delete(
        f"/v1/users/{bootstrap.superuser_id}/keys/{new_key['id']}", headers=auth(key)
    )
    assert r.status_code == 204
    r = await client.get("/v1/users/me", headers=auth(new_key["api_key"]))
    assert r.status_code == 401
