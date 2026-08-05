"""OIDC login for the admin UI (BUILD_PLAN § Admin UI & human auth).

Purely additive: tenants with an OidcConfig get an SSO button on the login
page; local email/password auth always works. Authlib drives the code flow
(discovery, state/nonce, JWKS, id_token validation); we only map the
IdP-asserted email to an existing user — no just-in-time provisioning, so
an owner must create the user (and team memberships) first.
"""

import uuid

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.config import get_settings
from sleeper_service.crypto import decrypt
from sleeper_service.db.models import OidcConfig, Team, TeamMember, User
from sleeper_service.db.session import get_db
from sleeper_service.runtime.outbound import (
    OutboundUrlError,
    validate_callback_target,
    validate_callback_url,
)
from sleeper_service.ui.routes import render_login, rotate_csrf_token

router = APIRouter(prefix="/ui/oidc", include_in_schema=False)

DISCOVERY_TIMEOUT_S = 10.0

# Only what the code flow needs. Anything else the IdP advertises (extra
# endpoints, and keys that collide with Authlib client config) is dropped.
_METADATA_KEYS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "id_token_signing_alg_values_supported",
)


class OidcDiscoveryError(Exception):
    pass


async def _discover(config: OidcConfig) -> dict:
    """Fetch and validate the IdP's discovery document.

    Validating the issuer alone is not enough: Authlib would fetch discovery
    itself and then POST the tenant's client secret to whatever
    ``token_endpoint`` the document advertises, and fetch JWKS from whatever
    ``jwks_uri`` it names — a tenant admin with a public issuer could point
    either at an internal address. So we resolve and check every endpoint the
    flow contacts server-side, and hand Authlib pre-loaded metadata instead of
    a URL so it never re-fetches from a destination we have not checked.
    """
    allow_loopback = get_settings().oidc_allow_loopback_issuers
    url = f"{config.issuer}/.well-known/openid-configuration"
    await validate_callback_target(url, allow_loopback=allow_loopback, label="OIDC issuer")
    async with httpx.AsyncClient(timeout=DISCOVERY_TIMEOUT_S, follow_redirects=False) as http:
        response = await http.get(url)
        response.raise_for_status()
        metadata = response.json()
    if not isinstance(metadata, dict):
        raise OidcDiscoveryError("discovery document is not a JSON object")
    # RFC 8414 §3.3: the advertised issuer must match the one we asked about,
    # so a hostile document cannot move the id_token `iss` trust anchor.
    if str(metadata.get("issuer", "")).rstrip("/") != config.issuer.rstrip("/"):
        raise OidcDiscoveryError("discovery document issuer does not match the configured issuer")
    for key in ("token_endpoint", "jwks_uri"):
        if not metadata.get(key):
            raise OidcDiscoveryError(f"discovery document has no {key}")
        await validate_callback_target(
            str(metadata[key]), allow_loopback=allow_loopback, label=f"OIDC {key}"
        )
    # Browser-side redirect, not a server-side fetch: policy only, no resolution.
    validate_callback_url(
        str(metadata.get("authorization_endpoint", "")),
        allow_loopback=allow_loopback,
        label="OIDC authorization_endpoint",
    )
    return {k: metadata[k] for k in _METADATA_KEYS if k in metadata}


def _client(config: OidcConfig, metadata: dict):
    """A per-request Authlib client: config is per-tenant and mutable, so
    nothing is cached at module scope."""
    oauth = OAuth()
    client = oauth.register(
        name="idp",
        client_id=config.client_id,
        client_secret=decrypt(config.client_secret_enc),
        client_kwargs={"scope": config.scopes},
    )
    # No server_metadata_url: with metadata already loaded, Authlib's
    # load_server_metadata() is a no-op and issues no unvalidated request.
    client.server_metadata.update(metadata)
    return client


async def _config(db: AsyncSession, tenant_id: uuid.UUID) -> OidcConfig | None:
    return await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant_id))


@router.get("/{tenant_id}/login")
async def oidc_login(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    config = await _config(db, tenant_id)
    if config is None:
        return RedirectResponse("/ui/login", status_code=303)
    try:
        metadata = await _discover(config)
    except (OutboundUrlError, OidcDiscoveryError, httpx.HTTPError, ValueError):
        return await render_login(
            request, db, "SSO failed: the identity provider could not be validated", status_code=400
        )
    redirect_uri = str(request.url_for("oidc_callback", tenant_id=tenant_id))
    return await _client(config, metadata).authorize_redirect(request, redirect_uri)


@router.get("/{tenant_id}/callback")
async def oidc_callback(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    config = await _config(db, tenant_id)
    if config is None:
        return RedirectResponse("/ui/login", status_code=303)
    # Revalidated here, not carried over from login: the token POST happens on
    # this request, and DNS can move between the two.
    try:
        metadata = await _discover(config)
    except (OutboundUrlError, OidcDiscoveryError, httpx.HTTPError, ValueError):
        return await render_login(
            request, db, "SSO failed: the identity provider could not be validated", status_code=400
        )
    try:
        token = await _client(config, metadata).authorize_access_token(request)
    except OAuthError as e:
        return await render_login(request, db, f"SSO failed: {e.error}", status_code=401)

    claims = token.get("userinfo") or {}
    email = claims.get("email")
    if not email or claims.get("email_verified") is not True:
        return await render_login(
            request,
            db,
            "SSO failed: the identity provider did not assert a verified email",
            status_code=401,
        )
    user = await db.scalar(select(User).where(func.lower(User.email) == email.lower()))
    membership = None
    if user is not None and not user.is_superuser:
        membership = await db.scalar(
            select(TeamMember.user_id)
            .join(Team, Team.id == TeamMember.team_id)
            .where(TeamMember.user_id == user.id, Team.tenant_id == tenant_id)
            .limit(1)
        )
    if user is None or user.is_superuser or membership is None:
        return await render_login(
            request,
            db,
            "No eligible Sleeper Service account for this tenant",
            status_code=403,
        )
    request.session.clear()
    request.session.update(
        {
            "user_id": str(user.id),
            # Display preference (which tenant the UI opens on)...
            "tenant_id": str(tenant_id),
            # ...and the authorization boundary. `ui_user` narrows the
            # principal's roles to teams inside this tenant, so a tenant's own
            # IdP cannot mint a session carrying the user's roles elsewhere.
            "auth_tenant_id": str(tenant_id),
        }
    )
    rotate_csrf_token(request)
    return RedirectResponse("/ui", status_code=303)
