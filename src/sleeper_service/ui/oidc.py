"""OIDC login for the admin UI (BUILD_PLAN § Admin UI & human auth).

Purely additive: tenants with an OidcConfig get an SSO button on the login
page; local email/password auth always works. Authlib drives the code flow
(discovery, state/nonce, JWKS, id_token validation); we only map the
IdP-asserted email to an existing user — no just-in-time provisioning, so
an owner must create the user (and team memberships) first.
"""

import uuid

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.crypto import decrypt
from sleeper_service.db.models import OidcConfig, Team, TeamMember, User
from sleeper_service.db.session import get_db
from sleeper_service.ui.routes import _csrf_token, render_login

router = APIRouter(prefix="/ui/oidc", include_in_schema=False)


def _client(config: OidcConfig):
    """A per-request Authlib client: config is per-tenant and mutable, so
    nothing is cached at module scope."""
    oauth = OAuth()
    return oauth.register(
        name="idp",
        server_metadata_url=f"{config.issuer}/.well-known/openid-configuration",
        client_id=config.client_id,
        client_secret=decrypt(config.client_secret_enc),
        client_kwargs={"scope": config.scopes},
    )


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
    redirect_uri = str(request.url_for("oidc_callback", tenant_id=tenant_id))
    return await _client(config).authorize_redirect(request, redirect_uri)


@router.get("/{tenant_id}/callback")
async def oidc_callback(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    config = await _config(db, tenant_id)
    if config is None:
        return RedirectResponse("/ui/login", status_code=303)
    try:
        token = await _client(config).authorize_access_token(request)
    except OAuthError as e:
        return await render_login(request, db, f"SSO failed: {e.error}", status_code=401)

    claims = token.get("userinfo") or {}
    email = claims.get("email")
    if not email or claims.get("email_verified") is not True:
        return await render_login(
            request, db, "SSO failed: the identity provider did not assert a verified email",
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
    csrf_token = _csrf_token(request)
    request.session.clear()
    request.session.update(
        {"user_id": str(user.id), "tenant_id": str(tenant_id), "csrf_token": csrf_token}
    )
    return RedirectResponse("/ui", status_code=303)
