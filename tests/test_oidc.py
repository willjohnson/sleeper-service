"""OIDC login (BUILD_PLAN § Admin UI & human auth): per-tenant config API +
the full Authlib code flow against a local stub IdP.

The stub runs as a real uvicorn server in the test loop because Authlib
fetches discovery metadata, JWKS, and tokens over real HTTP — so the e2e
test exercises genuine state/nonce/signature/audience validation. The stub's
token endpoint reads `code` as "<nonce>:<email>", letting each test choose
the identity the IdP asserts.
"""

import asyncio
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import uvicorn
from fastapi import FastAPI, Request
from httpx import AsyncClient
from joserfc import jwt as jose_jwt
from joserfc.jwk import RSAKey

from sleeper_service.config import get_settings
from tests.conftest import auth

CLIENT_ID = "sleeper-ui"
CLIENT_SECRET = "stub-idp-secret"


@pytest.fixture
async def idp(unused_tcp_port: int, monkeypatch) -> dict:
    # The stub runs on 127.0.0.1 and issuer validation rejects loopback in
    # production, so the e2e flow needs the dev hatch. Scoped to this fixture:
    # every other test sees the production default.
    monkeypatch.setattr(get_settings(), "oidc_allow_loopback_issuers", True)
    issuer = f"http://127.0.0.1:{unused_tcp_port}"
    key = RSAKey.generate_key(2048, parameters={"kid": "test", "use": "sig", "alg": "RS256"})
    # tests mutate this to make the IdP advertise hostile metadata
    overrides: dict = {}

    stub = FastAPI()

    @stub.get("/.well-known/openid-configuration")
    def metadata() -> dict:
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            **overrides,
        }

    @stub.get("/jwks")
    def jwks() -> dict:
        return {"keys": [key.as_dict(private=False)]}

    @stub.post("/token")
    async def token(request: Request) -> dict:
        form = await request.form()
        nonce, _, email = str(form["code"]).partition(":")
        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": CLIENT_ID,
            "sub": "stub-subject",
            "email": email,
            "email_verified": True,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
        }
        id_token = jose_jwt.encode({"alg": "RS256", "kid": "test"}, claims, key)
        return {
            "access_token": "stub-access-token",
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token,
        }

    server = uvicorn.Server(
        uvicorn.Config(stub, host="127.0.0.1", port=unused_tcp_port, log_level="warning")
    )
    serve_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    yield {"issuer": issuer, "metadata_overrides": overrides}
    server.should_exit = True
    await serve_task


async def _configure(client: AsyncClient, root: dict, tenant_id: str, issuer: str) -> None:
    r = await client.put(
        f"/v1/tenants/{tenant_id}/oidc",
        headers=root,
        json={"issuer": issuer, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
    )
    assert r.status_code == 200, r.text


async def _start_sso(client: AsyncClient, tenant_id: str, issuer: str) -> tuple[str, str]:
    """Kick off the flow; returns (state, nonce) parsed from the IdP redirect."""
    r = await client.get(f"/ui/oidc/{tenant_id}/login", follow_redirects=False)
    assert r.status_code == 302, r.text
    location = r.headers["location"]
    assert location.startswith(f"{issuer}/authorize?")
    qs = parse_qs(urlsplit(location).query)
    assert qs["client_id"] == [CLIENT_ID]
    assert qs["redirect_uri"] == [f"http://test/ui/oidc/{tenant_id}/callback"]
    return qs["state"][0], qs["nonce"][0]


# --- Config API ---


async def test_oidc_config_rbac_and_secrecy(client: AsyncClient, org: dict, bootstrap) -> None:
    root = auth(bootstrap.superuser_key)
    alice = auth(org["users"]["alice"]["api_key"])  # team owner, not tenant admin
    tenant_id = org["tenant"]["id"]
    body = {"issuer": "https://idp.example.com/", "client_id": "cid", "client_secret": "s3cret"}

    r = await client.put(f"/v1/tenants/{tenant_id}/oidc", headers=alice, json=body)
    assert r.status_code == 403

    r = await client.put(f"/v1/tenants/{tenant_id}/oidc", headers=root, json=body)
    assert r.status_code == 200
    cfg = r.json()
    assert cfg["issuer"] == "https://idp.example.com"  # trailing slash stripped
    assert cfg["scopes"] == "openid email profile"
    assert "s3cret" not in r.text and "client_secret" not in cfg

    # upsert keeps one row per tenant
    body["client_id"] = "cid-2"
    r = await client.put(f"/v1/tenants/{tenant_id}/oidc", headers=root, json=body)
    assert r.status_code == 200 and r.json()["client_id"] == "cid-2"
    r = await client.get(f"/v1/tenants/{tenant_id}/oidc", headers=root)
    assert r.status_code == 200 and r.json()["id"] == cfg["id"]

    # the login page offers SSO once the org names itself...
    r = await client.get("/ui/login", params={"org": "acme"})
    assert "Continue with acme SSO" in r.text
    assert str(tenant_id) in r.text
    # ...and case-insensitively
    r = await client.get("/ui/login", params={"org": "ACME"})
    assert "Continue with acme SSO" in r.text

    # ...but the bare page must not enumerate tenants to anonymous callers:
    # no customer names, no tenant UUIDs (audit 4 #4).
    r = await client.get("/ui/login")
    assert "Continue with acme SSO" not in r.text
    assert str(tenant_id) not in r.text
    assert "acme" not in r.text

    # an unknown org gets no SSO button
    r = await client.get("/ui/login", params={"org": "no-such-org"})
    assert "Continue with no-such-org SSO" not in r.text

    r = await client.delete(f"/v1/tenants/{tenant_id}/oidc", headers=root)
    assert r.status_code == 204
    r = await client.get(f"/v1/tenants/{tenant_id}/oidc", headers=root)
    assert r.status_code == 404
    r = await client.get("/ui/login", params={"org": "acme"})
    assert "Continue with acme SSO" not in r.text


async def test_oidc_config_bad_issuer_rejected(client: AsyncClient, org: dict, bootstrap) -> None:
    root = auth(bootstrap.superuser_key)
    r = await client.put(
        f"/v1/tenants/{org['tenant']['id']}/oidc",
        headers=root,
        json={"issuer": "ldap://nope", "client_id": "c", "client_secret": "s"},
    )
    assert r.status_code == 422


async def test_oidc_config_rejects_private_issuer(
    client: AsyncClient, org: dict, bootstrap
) -> None:
    """A tenant-admin-controlled issuer is a server-side request target —
    reject non-global destinations like any other outbound URL. No `idp`
    fixture here, so the loopback dev hatch is off, as in production."""
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    # metadata IP literal
    r = await client.put(
        f"/v1/tenants/{tenant_id}/oidc",
        headers=root,
        json={
            "issuer": "http://169.254.169.254/latest",
            "client_id": "c",
            "client_secret": "s",
        },
    )
    assert r.status_code == 422
    assert "non-public" in r.json()["detail"]
    # loopback hostname (no dev hatch on in tests by default)
    r = await client.put(
        f"/v1/tenants/{tenant_id}/oidc",
        headers=root,
        json={"issuer": "http://localhost:8080/", "client_id": "c", "client_secret": "s"},
    )
    assert r.status_code == 422
    # credentials in the issuer URL
    r = await client.put(
        f"/v1/tenants/{tenant_id}/oidc",
        headers=root,
        json={
            "issuer": "https://user:pass@idp.example.com/",
            "client_id": "c",
            "client_secret": "s",
        },
    )
    assert r.status_code == 422
    # a clean public issuer is accepted
    r = await client.put(
        f"/v1/tenants/{tenant_id}/oidc",
        headers=root,
        json={"issuer": "https://idp.example.com/", "client_id": "c", "client_secret": "s"},
    )
    assert r.status_code == 200


# --- Login flow (e2e against the stub IdP) ---


async def test_oidc_login_end_to_end(client: AsyncClient, org: dict, bootstrap, idp: dict) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])

    state, nonce = await _start_sso(client, tenant_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{tenant_id}/callback",
        params={"code": f"{nonce}:bob@example.com", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/ui"

    # the session is real: /ui routes to bob's tenant, not back to login
    r = await client.get("/ui", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/ui/t/{tenant_id}"


async def test_oidc_session_is_scoped_to_the_authenticating_tenant(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    """Audit 4 #1: a tenant's IdP is configured by that tenant's own admin, so
    the session it mints must not carry the user's roles in *other* tenants.
    Otherwise a tenant admin points their IdP at a user who happens to be a
    member of their tenant and inherits that user's access everywhere else."""
    root = auth(bootstrap.superuser_key)
    acme_id = org["tenant"]["id"]

    # bob also belongs to a second, unrelated tenant
    r = await client.post("/v1/tenants", headers=root, json={"name": "other"})
    assert r.status_code == 201
    other_id = r.json()["id"]
    r = await client.post(
        f"/v1/tenants/{other_id}/teams",
        headers=root,
        json={"name": "secrets", "owner_user_id": org["users"]["bob"]["id"]},
    )
    assert r.status_code == 201

    # local password auth keeps bob's full scope: both tenants are visible
    r = await client.post(
        "/ui/login",
        data={
            "email": "bob@example.com",
            "password": "password-123",
            "_csrf_token": await _csrf(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    r = await client.get(f"/ui/t/{other_id}", follow_redirects=False)
    assert r.status_code == 200, "local login should see every tenant bob belongs to"
    await client.post("/ui/logout", data={"_csrf_token": await _csrf(client)})

    # SSO through acme's IdP authenticates bob, but only for acme
    await _configure(client, root, acme_id, idp["issuer"])
    state, nonce = await _start_sso(client, acme_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{acme_id}/callback",
        params={"code": f"{nonce}:bob@example.com", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/ui"

    r = await client.get("/ui", follow_redirects=False)
    assert r.headers["location"] == f"/ui/t/{acme_id}"
    r = await client.get(f"/ui/t/{acme_id}", follow_redirects=False)
    assert r.status_code == 200

    # the other tenant is not reachable from this session
    r = await client.get(f"/ui/t/{other_id}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui"


async def _csrf(client: AsyncClient) -> str:
    r = await client.get("/ui/login")
    match = re.search(r'name="_csrf_token" value="([^"]+)"', r.text)
    assert match is not None
    return match.group(1)


async def test_sso_login_rotates_the_csrf_token(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    """The SSO callback rebuilds the session; the CSRF token must be rebuilt
    with it rather than carried over from the pre-authentication session."""
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])

    pre_auth = await _csrf(client)
    state, nonce = await _start_sso(client, tenant_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{tenant_id}/callback",
        params={"code": f"{nonce}:bob@example.com", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 303

    assert await _csrf(client) != pre_auth


async def test_oidc_unknown_email_rejected(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])

    state, nonce = await _start_sso(client, tenant_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{tenant_id}/callback",
        params={"code": f"{nonce}:stranger@example.com", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert "No eligible Sleeper Service account" in r.text

    r = await client.get("/ui", follow_redirects=False)
    assert r.headers["location"] == "/ui/login"  # no session was created


async def test_oidc_forged_state_rejected(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])

    _state, nonce = await _start_sso(client, tenant_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{tenant_id}/callback",
        params={"code": f"{nonce}:bob@example.com", "state": "forged-state"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert "SSO failed" in r.text


async def test_oidc_metadata_endpoints_are_validated(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    """A public issuer whose discovery document points the token endpoint at an
    internal address must not get the tenant's client secret POSTed there —
    validating the issuer alone leaves the SSRF one level down."""
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])
    overrides = idp["metadata_overrides"]

    for hostile in (
        {"token_endpoint": "http://169.254.169.254/latest/meta-data/"},
        {"jwks_uri": "http://10.0.0.7:8200/v1/secret"},
        {"issuer": "https://someone-elses-idp.example.com"},
    ):
        overrides.clear()
        overrides.update(hostile)
        r = await client.get(f"/ui/oidc/{tenant_id}/login", follow_redirects=False)
        assert r.status_code == 400, f"{hostile} was not rejected: {r.status_code}"
        assert "could not be validated" in r.text

    # the honest document still works
    overrides.clear()
    state, _nonce = await _start_sso(client, tenant_id, idp["issuer"])
    assert state


async def test_oidc_login_unconfigured_tenant_redirects(client: AsyncClient, org: dict) -> None:
    r = await client.get(f"/ui/oidc/{org['tenant']['id']}/login", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"


async def test_tenant_oidc_cannot_authenticate_superuser(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])

    state, nonce = await _start_sso(client, tenant_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{tenant_id}/callback",
        params={"code": f"{nonce}:root@example.com", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 403
    r = await client.get("/ui", follow_redirects=False)
    assert r.headers["location"] == "/ui/login"


async def test_tenant_oidc_requires_membership(
    client: AsyncClient, org: dict, bootstrap, idp: dict
) -> None:
    root = auth(bootstrap.superuser_key)
    tenant_id = org["tenant"]["id"]
    await _configure(client, root, tenant_id, idp["issuer"])

    state, nonce = await _start_sso(client, tenant_id, idp["issuer"])
    r = await client.get(
        f"/ui/oidc/{tenant_id}/callback",
        params={"code": f"{nonce}:dave@example.com", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 403
