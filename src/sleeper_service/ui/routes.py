"""Admin UI: server-rendered, session-authenticated, per-tenant.

Deviation from BUILD_PLAN (2026-08-02): plain session-cookie auth against the
existing users table instead of fastapi-users — we already own the user rows
and pwdlib hashing, so fastapi-users would add machinery without adding
capability. OIDC remains planned as an additive option.

RBAC mirrors the API exactly: any team role makes a thing visible; owner
promotes versions and approves memory; editor retries jobs.
"""

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

import anyio
import jsonschema
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import escape
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service import storage
from sleeper_service.api.v1.agents import GOVERNED_OPTION_KEYS
from sleeper_service.api.v1.events import render_template
from sleeper_service.api.v1.files import MAX_FILE_SIZE, sniff_content_type
from sleeper_service.api.v1.schemas import JobContext
from sleeper_service.auth.keys import generate_key, hash_key
from sleeper_service.auth.passwords import hash_password, verify_password
from sleeper_service.auth.principal import UserPrincipal
from sleeper_service.auth.rbac import is_tenant_admin, visible_team_ids
from sleeper_service.config import get_settings
from sleeper_service.constants import KeyKind, KeyScope, Role
from sleeper_service.crypto import encrypt
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    ApiKey,
    DataStore,
    EvalCase,
    EvalRun,
    EventSource,
    Feedback,
    File,
    Job,
    JobEvent,
    McpServer,
    MemoryVersion,
    Model,
    NotifChannel,
    OidcConfig,
    ProviderCred,
    Team,
    TeamMember,
    Tenant,
    User,
    VersionAlias,
)
from sleeper_service.db.session import get_db
from sleeper_service.runtime import spending
from sleeper_service.runtime.evals import PATH_OPS, validate_checks
from sleeper_service.runtime.hooks import validate_hooks_settings
from sleeper_service.runtime.learning import validate_learning_settings
from sleeper_service.runtime.memory import latest_memory, learning_enabled
from sleeper_service.runtime.outbound import (
    OutboundUrlError,
    notif_policy,
    validate_apprise_url,
    validate_callback_url,
    validate_mcp_url,
)
from sleeper_service.runtime.providers import SUPPORTED_PROVIDERS
from sleeper_service.runtime.retention import file_expiry

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def client_ip(request: Request) -> str:
    """The requesting client's address, seeing through trusted proxies.

    Behind a reverse proxy every request arrives from the proxy, so keying a
    per-IP limit on the peer address collapses it to a single global bucket —
    for the login limiter that means one attacker can spend a victim's whole
    budget and lock them out, from anywhere.

    X-Forwarded-For fixes that but is client-controlled, so it is only
    consulted when `trusted_proxy_hops` says how many proxies are actually in
    front. Each proxy appends the address it received from, so with N trusted
    hops the client sits N from the right; anything an attacker prepends stays
    to the left of that and is never selected. Falls back to the peer address
    whenever the header is missing, short, or not an address.
    """
    peer = request.client.host if request.client else "unknown"
    hops = get_settings().trusted_proxy_hops
    if hops <= 0:
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    if not parts:
        return peer
    candidate = parts[-hops] if len(parts) >= hops else parts[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer


def rotate_csrf_token(request: Request) -> str:
    """Mint a fresh CSRF token, discarding any prior one.

    Called on every successful login, local or SSO. Carrying the
    pre-authentication token into the authenticated session would leave the
    token known to whoever established that pre-auth session: an attacker who
    can plant their own session cookie on the victim's browser learns the
    token, and it keeps working after the victim logs in — enough to forge
    state-changing requests as them. Rotating on the privilege change is the
    same reason the session itself is rebuilt here.
    """
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token


async def _csrf_protect(request: Request) -> None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    form = await request.form()
    supplied = str(form.get("_csrf_token", ""))
    expected = str(request.session.get("csrf_token", ""))
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid CSRF token")


router = APIRouter(
    prefix="/ui",
    include_in_schema=False,
    dependencies=[Depends(_csrf_protect)],
)


class NotAuthenticated(Exception):
    pass


async def ui_user(request: Request, db: AsyncSession = Depends(get_db)) -> UserPrincipal:
    user_id = request.session.get("user_id")
    if not user_id:
        raise NotAuthenticated
    user = await db.get(User, uuid.UUID(user_id))
    if user is None:
        raise NotAuthenticated
    memberships = await db.scalars(select(TeamMember).where(TeamMember.user_id == user.id))
    roles = {m.team_id: Role(m.role) for m in memberships}

    # An SSO session is scoped to the tenant whose IdP authenticated it. That
    # IdP is configured by that tenant's own admin, so it must not be able to
    # mint a session carrying the user's roles in *other* tenants — the
    # callback's membership check gates entry to the flow, not its scope.
    # Local password auth is an instance-controlled credential and keeps the
    # user's full scope.
    auth_tenant_id = request.session.get("auth_tenant_id")
    if auth_tenant_id is not None:
        roles = await _roles_within_tenant(db, roles, uuid.UUID(auth_tenant_id))
    # Resolved here, once, because the sidebar on every page needs it: without
    # it each render would have to remember to ask, and the one that forgot
    # would quietly drop the Settings link for an admin.
    request.state.admin_tenant_ids = await _admin_tenant_ids(db, user, roles)
    return UserPrincipal(user=user, roles=roles)


async def _admin_tenant_ids(
    db: AsyncSession, user: User, roles: dict[uuid.UUID, Role]
) -> set[uuid.UUID]:
    """Tenants this session administers, by rbac.is_tenant_admin's rule:
    superuser, or owner of the tenant's org-wide team."""
    if user.is_superuser:
        return set(await db.scalars(select(Tenant.id)))
    owned = [team_id for team_id, role in roles.items() if role == Role.OWNER]
    if not owned:
        return set()
    return set(
        await db.scalars(
            select(Team.tenant_id).where(Team.id.in_(owned), Team.is_org_team.is_(True))
        )
    )


async def _roles_within_tenant(
    db: AsyncSession, roles: dict[uuid.UUID, Role], tenant_id: uuid.UUID
) -> dict[uuid.UUID, Role]:
    if not roles:
        return roles
    scoped = set(
        await db.scalars(
            select(Team.id).where(Team.id.in_(list(roles)), Team.tenant_id == tenant_id)
        )
    )
    return {team_id: role for team_id, role in roles.items() if team_id in scoped}


async def _visible_tenants(db: AsyncSession, p: UserPrincipal) -> list[Tenant]:
    if p.is_superuser:
        return list(await db.scalars(select(Tenant).order_by(Tenant.name)))
    if not p.roles:
        return []
    stmt = (
        select(Tenant)
        .join(Team, Team.tenant_id == Tenant.id)
        .where(Team.id.in_(list(p.roles)))
        .distinct()
        .order_by(Tenant.name)
    )
    return list(await db.scalars(stmt))


async def _tenant_or_home(
    db: AsyncSession, p: UserPrincipal, tenant_id: uuid.UUID
) -> Tenant | RedirectResponse:
    tenants = await _visible_tenants(db, p)
    tenant = next((t for t in tenants if t.id == tenant_id), None)
    if tenant is None:
        return RedirectResponse("/ui", status_code=303)
    return tenant


# Blank check rows offered on the new-eval-case form.
CHECK_ROWS = 4

# Deliberately loose, matching what a browser's type=email accepts: the API
# validates with EmailStr, but rejecting an address the user's own IdP will
# later assert is worse than accepting one that bounces.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _flash(request: Request, message: str) -> None:
    """One-shot error for a POST that redirects instead of re-rendering; the
    next page render picks it up as `error`."""
    request.session["flash"] = message


def _ctx(request: Request, p: UserPrincipal, **extra) -> dict:
    ctx = {
        "request": request,
        "user": p.user,
        "csrf_token": _csrf_token(request),
        **extra,
    }
    tenant = ctx.get("tenant")
    ctx["tenant_admin"] = tenant is not None and tenant.id in getattr(
        request.state, "admin_tenant_ids", set()
    )
    flash = request.session.pop("flash", None)
    if flash and not ctx.get("error"):
        ctx["error"] = flash
    return ctx


async def _team_role(db: AsyncSession, p: UserPrincipal, team_id: uuid.UUID) -> Role | None:
    if p.is_superuser:
        return Role.OWNER
    return p.roles.get(team_id)


async def _model_strings(db: AsyncSession) -> list[str]:
    return list(await db.scalars(select(Model.model_string).order_by(Model.model_string)))


# Bounds mirror api.v1.schemas.VersionCreate — the UI must not accept what the
# API would reject.
def _form_int(raw: str, default: int, lo: int, hi: int, label: str) -> tuple[int, str | None]:
    try:
        value = int(raw)
    except ValueError:
        return default, f"{label} must be a whole number."
    if not lo <= value <= hi:
        return default, f"{label} must be between {lo} and {hi}."
    return value, None


def _row_at(values: list[str], i: int, default: str = "") -> str:
    """The i-th value of a repeated form field. The parallel lists are only as
    long as the browser made them, and zipping them would drop a whole grant
    when one arm is shorter — the row's identity (the picked store or server)
    decides how many rows there are, never the fields beside it."""
    return values[i] if i < len(values) else default


def _store_grants_from_form(stores: list[str], prefixes: list[str], modes: list[str]) -> list:
    """Grant rows -> data_store_grants, shaped as runtime/toolsets reads them:
    {"store", "prefix", "mode"}. A row with no store picked is a blank row, not
    an error — the form always offers more rows than most versions use."""
    grants = []
    for i, store in enumerate(stores):
        store = store.strip()
        if not store:
            continue
        mode = _row_at(modes, i, "ro")
        grants.append(
            {
                "store": store,
                "prefix": _row_at(prefixes, i).strip().strip("/"),
                "mode": mode if mode in STORE_MODES else "ro",
            }
        )
    return grants


def _tool_grants_from_form(servers: list[str], tools: list[str]) -> list:
    """Grant rows -> tool_grants: {"server", "tools"}. An empty tool list means
    every tool the server offers, so it is omitted rather than sent as []."""
    grants = []
    for i, server in enumerate(servers):
        server = server.strip()
        if not server:
            continue
        names = [t.strip() for t in _row_at(tools, i).split(",") if t.strip()]
        grant = {"server": server}
        if names:
            grant["tools"] = names
        grants.append(grant)
    return grants


def _grant_rows(grants: list | None, keys: tuple[str, ...], blanks: int) -> list[tuple]:
    """Existing grants as form rows, padded with blanks. Values are read back
    out of whatever the version stored, so a grant written by the API with
    fields the form does not offer still round-trips its recognised parts."""
    rows = []
    for g in grants or []:
        if not isinstance(g, dict):
            continue
        row = []
        for key in keys:
            value = g.get(key, "")
            row.append(", ".join(value) if isinstance(value, list) else str(value or ""))
        rows.append(tuple(row))
    rows += [("",) * len(keys)] * max(0, blanks - len(rows))
    return rows


def _pretty_json(value: dict | list | None) -> str:
    """Indented JSON for a form field or a <pre>; empty for nothing to show,
    so a blank textarea and an unset column render the same way."""
    if not value:
        return ""
    return json.dumps(value, indent=2)


def _form_json_object(
    raw: str, label: str, *, as_schema: bool = False
) -> tuple[dict | None, str | None]:
    """Parse an optional JSON-object field. Blank means unset, which is not the
    same as `{}` — an empty output schema would still force structured output.

    Schemas are additionally checked as JSON Schema. The API takes any dict
    here, but a malformed schema is not caught until the runner builds an
    output type from it, by which point every job on the version fails; the
    form is the last place it can be a correction rather than an outage."""
    raw = raw.strip()
    if not raw:
        return None, None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{label} is not valid JSON: {exc.msg} (line {exc.lineno})."
    if not isinstance(value, dict):
        return None, f"{label} must be a JSON object, not {type(value).__name__}."
    if as_schema:
        try:
            jsonschema.Draft202012Validator.check_schema(value)
        except jsonschema.SchemaError as exc:
            return None, f"{label} is not a valid JSON Schema: {exc.message}"
    return value, None


async def _clean_agent_fields(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    name: str,
    spending_limit: str,
    *,
    exclude: uuid.UUID | None = None,
) -> tuple[str, Decimal | None, str | None]:
    """Shared by create and edit. Returns (name, limit, error message)."""
    name = name.strip()
    if not name:
        return name, None, "Name is required."
    if len(name) > 200:
        return name, None, "Name must be 200 characters or fewer."
    stmt = select(Agent).where(Agent.tenant_id == tenant_id, Agent.name == name)
    if exclude is not None:
        stmt = stmt.where(Agent.id != exclude)
    if await db.scalar(stmt):
        return name, None, f"An agent named {name!r} already exists in this tenant."

    limit = None
    raw = spending_limit.strip()
    if raw:
        try:
            limit = Decimal(raw)
        except InvalidOperation:
            return name, None, "Spending limit must be a number, or blank for no limit."
        if limit <= 0:
            return name, None, "Spending limit must be greater than zero."
    return name, limit, None


def _options_from_form(
    delegation: str, memory: bool, learning: bool, memory_approval: bool
) -> dict:
    options: dict = {}
    if delegation in ("team", "tenant"):
        options["delegation"] = delegation
    for key, value in (
        ("memory", memory),
        ("learning", learning),
        ("memory_approval", memory_approval),
    ):
        if value:
            options[key] = True
    return options


def _governed_change(old: dict, new: dict) -> bool:
    return any(bool(old.get(k)) != bool(new.get(k)) for k in GOVERNED_OPTION_KEYS)


async def _new_version(
    db: AsyncSession,
    agent: Agent,
    p: UserPrincipal,
    *,
    prompt: str,
    model: Model,
    max_iterations: int,
    timeout_s: int,
    params: dict | None = None,
    input_schema: dict | None = None,
    output_schema: dict | None = None,
    tool_grants: list | None = None,
    data_store_grants: list | None = None,
) -> AgentVersion:
    """Append a version, auto-promoting the first one so a freshly created
    agent is immediately runnable (same rule as POST /v1/agents/{id}/versions).

    Grants default to empty rather than to the outgoing version's: the version
    form now collects them, and a caller that omits them means none. The
    create-agent path relies on that — a brand new agent has nothing to
    inherit."""
    next_no = (
        await db.scalar(
            select(func.coalesce(func.max(AgentVersion.version_no), 0)).where(
                AgentVersion.agent_id == agent.id
            )
        )
    ) + 1
    version = AgentVersion(
        agent_id=agent.id,
        version_no=next_no,
        prompt=prompt,
        model_id=model.id,
        params=params or {},
        max_iterations=max_iterations,
        timeout_s=timeout_s,
        tool_grants=tool_grants or [],
        data_store_grants=data_store_grants or [],
        input_schema=input_schema,
        output_schema=output_schema,
        created_by=p.user.id,
    )
    db.add(version)
    await db.flush()
    if agent.current_version_id is None:
        agent.current_version_id = version.id
    return version


# --- Auth ---


async def render_login(
    request: Request,
    db: AsyncSession,
    error: str | None,
    status_code: int = 200,
    org: str | None = None,
):
    """Login page (local auth always works), with an SSO button for the one
    organization named in `org`. Shared with the OIDC callback's error paths.

    Deliberately *not* a list of every OIDC-configured tenant: this page is
    reachable anonymously, so enumerating it would hand any passer-by the
    operator's customer names and their tenant UUIDs — the same identifiers
    used throughout /ui/t/{tenant_id} and /v1/tenants/{tenant_id}/…. Standard
    SSO discovery instead: the user names their org, we resolve exactly one.
    """
    sso = []
    if org and org.strip():
        row = (
            await db.execute(
                select(Tenant.id, Tenant.name)
                .join(OidcConfig, OidcConfig.tenant_id == Tenant.id)
                .where(func.lower(Tenant.name) == org.strip().lower())
            )
        ).first()
        if row is not None:
            sso = [row]
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": error,
            "sso": sso,
            "org": org or "",
            "org_missing": bool(org and org.strip()) and not sso,
            "csrf_token": _csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, org: str | None = None, db: AsyncSession = Depends(get_db)):
    return await render_login(request, db, None, org=org)


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    from sleeper_service.redis_client import get_redis

    settings = get_settings()
    identity = hashlib.sha256(f"{client_ip(request)}:{email.strip().lower()}".encode()).hexdigest()
    redis = get_redis()
    rate_key = f"ui-login:{identity}"
    count = await redis.incr(rate_key)
    if count == 1:
        await redis.expire(rate_key, settings.login_rate_window_s)
    if count > settings.login_rate_limit:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many login attempts",
            headers={"Retry-After": str(settings.login_rate_window_s)},
        )
    user = await db.scalar(select(User).where(User.email == email))
    if user is None or not user.password_hash or not verify_password(password, user.password_hash):
        return await render_login(request, db, "Invalid email or password", status_code=401)
    await redis.delete(rate_key)
    request.session.clear()
    request.session.update({"user_id": str(user.id)})
    rotate_csrf_token(request)
    return RedirectResponse("/ui", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/ui/login", status_code=303)


# --- Tenant selection ---


@router.get("/")
@router.get("")
async def home(
    request: Request,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenants = await _visible_tenants(db, p)
    if not tenants:
        return HTMLResponse("<p style='margin:40px'>No tenants visible for this account.</p>")
    stored = request.session.get("tenant_id")
    tenant = next((t for t in tenants if str(t.id) == stored), tenants[0])
    return RedirectResponse(f"/ui/t/{tenant.id}", status_code=303)


@router.get("/switch")
async def switch_tenant(request: Request, tenant_id: str):
    request.session["tenant_id"] = tenant_id
    return RedirectResponse(f"/ui/t/{tenant_id}", status_code=303)


# --- Dashboard ---


CHART_DAYS = 14


async def _activity_charts(db: AsyncSession, scope, now: datetime) -> dict:
    """Jobs-by-status and token totals bucketed by day over the last fortnight,
    plus the mean tokens a job burned in that window. `scope` narrows Job to a
    tenant or a single agent."""
    since = now - timedelta(days=CHART_DAYS - 1)
    day = func.date_trunc("day", Job.created_at)
    rows = (
        await db.execute(
            select(day.label("day"), Job.status, func.count())
            .where(scope, Job.created_at >= since)
            .group_by(day, Job.status)
        )
    ).all()
    token_rows = (
        await db.execute(
            select(day.label("day"), func.sum(Job.tokens_in), func.sum(Job.tokens_out))
            .where(scope, Job.created_at >= since)
            .group_by(day)
        )
    ).all()

    days = [(since + timedelta(days=i)).date() for i in range(CHART_DAYS)]
    labels = [d.strftime("%m-%d") for d in days]
    statuses = sorted({status for _, status, _ in rows})
    by_day_status = {(d.date(), s): c for d, s, c in rows}
    by_day_tokens = {d.date(): (ti or 0, to or 0) for d, ti, to in token_rows}
    jobs_total = sum(c for _, _, c in rows)
    tokens_total = sum(ti + to for ti, to in by_day_tokens.values())
    return {
        "jobs_chart": {
            "labels": labels,
            "statuses": [
                {"name": s, "counts": [by_day_status.get((d, s), 0) for d in days]}
                for s in statuses
            ],
        },
        "tokens_chart": {
            "labels": labels,
            "tokens_in": [by_day_tokens.get(d, (0, 0))[0] for d in days],
            "tokens_out": [by_day_tokens.get(d, (0, 0))[1] for d in days],
        },
        "jobs_total": jobs_total,
        "avg_tokens_per_job": (tokens_total / jobs_total) if jobs_total else 0,
    }


@router.get("/t/{tenant_id}", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant
    request.session["tenant_id"] = str(tenant.id)
    tenants = await _visible_tenants(db, p)
    visible_teams = await visible_team_ids(db, p, tenant.id)
    tenant_agents = select(Agent.id).where(
        Agent.tenant_id == tenant.id,
        Agent.team_id.in_(visible_teams),
    )
    now = datetime.now(UTC)

    total_agents = await db.scalar(
        select(func.count()).select_from(Agent).where(Agent.id.in_(tenant_agents))
    )
    live_agents = await db.scalar(
        select(func.count())
        .select_from(Agent)
        .where(Agent.id.in_(tenant_agents), Agent.current_version_id.is_not(None))
    )
    week_ago = now - timedelta(days=7)
    jobs_7d = await db.scalar(
        select(func.count())
        .select_from(Job)
        .where(Job.agent_id.in_(tenant_agents), Job.created_at >= week_ago)
    )
    succeeded_7d = await db.scalar(
        select(func.count())
        .select_from(Job)
        .where(
            Job.agent_id.in_(tenant_agents),
            Job.created_at >= week_ago,
            Job.status == "succeeded",
        )
    )
    cost_30d = await db.scalar(
        select(func.coalesce(func.sum(Job.cost), 0)).where(
            Job.agent_id.in_(tenant_agents),
            Job.created_at >= now - timedelta(days=30),
            Job.is_eval.is_(False),
        )
    )

    charts = await _activity_charts(db, Job.agent_id.in_(tenant_agents), now)

    recent = (
        await db.execute(
            select(Job, Agent.name)
            .join(Agent, Job.agent_id == Agent.id)
            .where(Job.agent_id.in_(tenant_agents))
            .order_by(Job.created_at.desc())
            .limit(12)
        )
    ).all()
    recent_jobs = [
        {
            "id": j.id,
            "agent_id": j.agent_id,
            "agent_name": name,
            "status": j.status,
            "tokens_in": j.tokens_in,
            "tokens_out": j.tokens_out,
            "cost": j.cost,
            "created_at": j.created_at,
        }
        for j, name in recent
    ]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=tenants,
            section="dashboard",
            stats={
                "total_agents": total_agents,
                "live_agents": live_agents,
                "jobs_7d": jobs_7d,
                "success_rate": (succeeded_7d / jobs_7d) if jobs_7d else 0,
                "cost_30d": cost_30d,
            },
            jobs_chart=json.dumps(charts["jobs_chart"]),
            tokens_chart=json.dumps(charts["tokens_chart"]),
            recent_jobs=recent_jobs,
        ),
    )


# --- Agents ---


@router.get("/t/{tenant_id}/agents", response_class=HTMLResponse)
async def agents_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant
    tenants = await _visible_tenants(db, p)
    week_ago = datetime.now(UTC) - timedelta(days=7)

    teams = list(
        await db.scalars(
            select(Team)
            .where(Team.tenant_id == tenant.id)
            .order_by(Team.is_org_team.desc(), Team.name)
        )
    )
    team_views = []
    creatable_teams = []
    for team in teams:
        role = await _team_role(db, p, team.id)
        if role is None:
            continue
        if role in (Role.OWNER, Role.EDITOR):
            creatable_teams.append(
                {"id": team.id, "name": team.name, "can_govern": role == Role.OWNER}
            )
        agents = list(
            await db.scalars(select(Agent).where(Agent.team_id == team.id).order_by(Agent.name))
        )
        agent_views = []
        archived_views = []
        for a in agents:
            if a.archived_at is not None:
                archived_views.append({"id": a.id, "name": a.name, "archived_at": a.archived_at})
                continue
            version = (
                await db.get(AgentVersion, a.current_version_id) if a.current_version_id else None
            )
            jobs_7d = await db.scalar(
                select(func.count())
                .select_from(Job)
                .where(Job.agent_id == a.id, Job.created_at >= week_ago, Job.is_eval.is_(False))
            )
            agent_views.append(
                {
                    "id": a.id,
                    "name": a.name,
                    "description": a.description,
                    "options": a.options or {},
                    "version_no": version.version_no if version else None,
                    "jobs_7d": jobs_7d,
                    "spend": float(await spending.month_spend(db, a.id)),
                    "spending_limit": float(a.spending_limit) if a.spending_limit else None,
                }
            )
        team_views.append(
            {
                "id": team.id,
                "name": team.name,
                "is_org_team": team.is_org_team,
                "role": role.value if role else None,
                "agents": agent_views,
                "archived": archived_views,
            }
        )

    return templates.TemplateResponse(
        request,
        "agents.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=tenants,
            section="agents",
            teams=team_views,
            can_create=bool(creatable_teams),
            can_create_team=await is_tenant_admin(db, p, tenant.id),
        ),
    )


async def _tenant_users(db: AsyncSession, tenant_id: uuid.UUID, me: User) -> list[User]:
    """Users who already belong to a team in this tenant.

    Users are global, so offering every user in the instance would disclose
    who exists in other tenants. A superuser creating a team in a tenant they
    are not a member of still needs to be able to pick themselves.
    """
    users = list(
        await db.scalars(
            select(User)
            .join(TeamMember, TeamMember.user_id == User.id)
            .join(Team, Team.id == TeamMember.team_id)
            .where(Team.tenant_id == tenant_id)
            .distinct()
            .order_by(User.email)
        )
    )
    if not any(u.id == me.id for u in users):
        users.insert(0, me)
    return users


async def _render_team(
    request: Request,
    team_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    created_key: ApiKey | None = None,
    plaintext: str | None = None,
    status_code: int = 200,
):
    team = await db.get(Team, team_id)
    if team is None:
        return RedirectResponse("/ui", status_code=303)
    role = await _team_role(db, p, team.id)
    if role is None:
        return RedirectResponse("/ui", status_code=303)

    rows = (
        await db.execute(
            select(TeamMember, User)
            .join(User, User.id == TeamMember.user_id)
            .where(TeamMember.team_id == team.id)
            .order_by(User.email)
        )
    ).all()
    owner_count = sum(1 for m, _ in rows if m.role == Role.OWNER)
    members = [
        {
            "user_id": u.id,
            "email": u.email,
            "role": m.role,
            "is_me": u.id == p.user.id,
            # Mirrors _forbid_removing_last_owner: the UI must not offer what
            # the API would refuse.
            "is_last_owner": m.role == Role.OWNER and owner_count <= 1,
        }
        for m, u in rows
    ]
    member_ids = {m["user_id"] for m in members}
    suggestions = [
        u.email for u in await _tenant_users(db, team.tenant_id, p.user) if u.id not in member_ids
    ]

    return templates.TemplateResponse(
        request,
        "team_detail.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, team.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            team=team,
            members=members,
            suggestions=suggestions,
            can_manage=role == Role.OWNER,
            roles=[r.value for r in Role],
            # Owner-only panels, and owner-only data: an Apprise subscription
            # and the list of providers a team pays for are both things a
            # viewer has no business reading, so they are not fetched at all
            # unless the panel is going to render.
            channels=await _team_channels(db, team.id) if role == Role.OWNER else [],
            creds=await _provider_creds(db, KeyScope.TEAM, team.id) if role == Role.OWNER else [],
            providers=PROVIDER_CHOICES,
            notif_events=NOTIF_EVENTS,
            invoke_keys=await _scoped_invoke_keys(db, KeyScope.TEAM, team.id)
            if role == Role.OWNER
            else [],
            created_key=created_key,
            plaintext=plaintext,
            error=error,
        ),
        status_code=status_code,
    )


@router.get("/teams/{team_id}", response_class=HTMLResponse)
async def team_page(
    request: Request,
    team_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_team(request, team_id, db, p)


async def _team_owner_or_redirect(
    db: AsyncSession, p: UserPrincipal, team_id: uuid.UUID
) -> tuple[Team | None, RedirectResponse | None]:
    team = await db.get(Team, team_id)
    if team is None:
        return None, RedirectResponse("/ui", status_code=303)
    if await _team_role(db, p, team.id) != Role.OWNER:
        return None, RedirectResponse(f"/ui/teams/{team_id}", status_code=303)
    return team, None


def _valid_role(raw: str) -> Role | None:
    try:
        return Role(raw)
    except ValueError:
        return None


@router.post("/teams/{team_id}/members")
async def ui_add_member(
    request: Request,
    team_id: uuid.UUID,
    email: str = Form(""),
    role: str = Form(Role.VIEWER.value),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect

    async def fail(message: str):
        return await _render_team(request, team_id, db, p, error=message, status_code=400)

    new_role = _valid_role(role)
    if new_role is None:
        return await fail("Pick a role.")
    email = email.strip().lower()
    if not email:
        return await fail("Email is required.")
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        return await fail(
            f"No user with the email {email!r}. Users are created by an instance "
            "superuser before they can join a team."
        )

    member = await db.get(TeamMember, (user.id, team.id))
    if member is None:
        db.add(TeamMember(user_id=user.id, team_id=team.id, role=new_role))
    else:
        member.role = new_role
    await db.commit()
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


@router.post("/teams/{team_id}/members/{user_id}/role")
async def ui_set_member_role(
    request: Request,
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect

    async def fail(message: str):
        return await _render_team(request, team_id, db, p, error=message, status_code=400)

    new_role = _valid_role(role)
    member = await db.get(TeamMember, (user_id, team_id))
    if new_role is None or member is None:
        return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)
    if member.role == Role.OWNER and new_role != Role.OWNER and await _is_last_owner(db, team_id):
        return await fail("Every team must keep at least one owner.")
    member.role = new_role
    await db.commit()
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


@router.post("/teams/{team_id}/members/{user_id}/remove")
async def ui_remove_member(
    request: Request,
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect

    member = await db.get(TeamMember, (user_id, team_id))
    if member is None:
        return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)
    if member.role == Role.OWNER and await _is_last_owner(db, team_id):
        return await _render_team(
            request,
            team_id,
            db,
            p,
            error="Every team must keep at least one owner.",
            status_code=400,
        )
    await db.delete(member)
    await db.commit()
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


async def _is_last_owner(db: AsyncSession, team_id: uuid.UUID) -> bool:
    owners = await db.scalar(
        select(func.count())
        .select_from(TeamMember)
        .where(TeamMember.team_id == team_id, TeamMember.role == Role.OWNER)
    )
    return owners <= 1


async def _render_new_team(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant
    if not await is_tenant_admin(db, p, tenant.id):
        return RedirectResponse(f"/ui/t/{tenant.id}/agents", status_code=303)

    return templates.TemplateResponse(
        request,
        "team_new.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="agents",
            candidates=await _tenant_users(db, tenant.id, p.user),
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/t/{tenant_id}/teams/new", response_class=HTMLResponse)
async def new_team_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_team(request, tenant_id, db, p)


@router.post("/t/{tenant_id}/teams")
async def ui_create_team(
    request: Request,
    tenant_id: uuid.UUID,
    name: str = Form(""),
    owner_user_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    """Mirrors POST /v1/tenants/{id}/teams: tenant admin only, and the team
    gets an owner from birth."""
    form = {"name": name, "owner_user_id": owner_user_id}

    async def fail(message: str):
        return await _render_new_team(
            request, tenant_id, db, p, error=message, form=form, status_code=400
        )

    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant
    if not await is_tenant_admin(db, p, tenant.id):
        return RedirectResponse(f"/ui/t/{tenant.id}/agents", status_code=303)

    name = name.strip()
    if not name:
        return await fail("Name is required.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    if await db.scalar(select(Team).where(Team.tenant_id == tenant.id, Team.name == name)):
        return await fail(f"A team named {name!r} already exists in this tenant.")

    owner = p.user
    if owner_user_id and owner_user_id != str(p.user.id):
        candidates = await _tenant_users(db, tenant.id, p.user)
        owner = next((u for u in candidates if str(u.id) == owner_user_id), None)
        if owner is None:
            return await fail("Pick an owner from this tenant.")

    team = Team(tenant_id=tenant.id, name=name)
    db.add(team)
    await db.flush()
    db.add(TeamMember(user_id=owner.id, team_id=team.id, role=Role.OWNER))
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant.id}/agents", status_code=303)


async def _render_new_agent(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    """The create form has its own page, so a failed submit re-renders here
    with the operator's input rather than dropping a long prompt."""
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant

    teams = list(
        await db.scalars(
            select(Team)
            .where(Team.tenant_id == tenant.id)
            .order_by(Team.is_org_team.desc(), Team.name)
        )
    )
    creatable = []
    for team in teams:
        role = await _team_role(db, p, team.id)
        if role in (Role.OWNER, Role.EDITOR):
            creatable.append({"id": team.id, "name": team.name, "can_govern": role == Role.OWNER})
    if not creatable:
        return RedirectResponse(f"/ui/t/{tenant.id}/agents", status_code=303)

    return templates.TemplateResponse(
        request,
        "agent_new.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="agents",
            creatable_teams=creatable,
            models=await _model_strings(db),
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/t/{tenant_id}/agents/new", response_class=HTMLResponse)
async def new_agent_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_agent(request, tenant_id, db, p)


@router.post("/t/{tenant_id}/agents")
async def ui_create_agent(
    request: Request,
    tenant_id: uuid.UUID,
    team_id: str = Form(""),
    name: str = Form(""),
    model: str = Form(""),
    prompt: str = Form(""),
    description: str = Form(""),
    spending_limit: str = Form(""),
    max_iterations: str = Form("10"),
    timeout_s: str = Form("300"),
    output_schema: str = Form(""),
    delegation: str = Form("none"),
    memory: bool = Form(False),
    learning: bool = Form(False),
    memory_approval: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    """Create an agent and its first version in one step.

    The API splits these across two calls, but an agent with no version cannot
    run a job, so the UI only ever produces runnable agents.
    """
    form = {
        "team_id": team_id,
        "name": name,
        "model": model,
        "prompt": prompt,
        "description": description,
        "spending_limit": spending_limit,
        "max_iterations": max_iterations,
        "timeout_s": timeout_s,
        "output_schema": output_schema,
        "delegation": delegation,
        "memory": memory,
        "learning": learning,
        "memory_approval": memory_approval,
    }

    async def fail(message: str):
        return await _render_new_agent(
            request, tenant_id, db, p, error=message, form=form, status_code=400
        )

    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant

    try:
        team = await db.get(Team, uuid.UUID(team_id))
    except ValueError:
        team = None
    if team is None or team.tenant_id != tenant.id:
        return await fail("Pick a team to own this agent.")
    role = await _team_role(db, p, team.id)
    if role not in (Role.OWNER, Role.EDITOR):
        return await fail(f"You need the editor role on {team.name} to create an agent there.")

    options = _options_from_form(delegation, memory, learning, memory_approval)
    if _governed_change({}, options) and role != Role.OWNER:
        return await fail(
            "Memory, learning and approval are owner-managed — ask an owner of "
            f"{team.name}, or create the agent without them."
        )

    name, limit, err = await _clean_agent_fields(db, tenant.id, name, spending_limit)
    if err:
        return await fail(err)

    prompt = prompt.strip()
    if not prompt:
        return await fail("The first version needs a prompt.")
    iterations, err = _form_int(max_iterations, 10, 1, 100, "Max iterations")
    if err:
        return await fail(err)
    timeout, err = _form_int(timeout_s, 300, 1, 3600, "Timeout")
    if err:
        return await fail(err)
    out_schema, err = _form_json_object(output_schema, "Output schema", as_schema=True)
    if err:
        return await fail(err)
    model_row = await db.scalar(select(Model).where(Model.model_string == model))
    if model_row is None:
        return await fail(f"Unknown model {model!r} — register it under Models first.")

    agent = Agent(
        tenant_id=tenant.id,
        team_id=team.id,
        name=name,
        description=description.strip(),
        spending_limit=limit,
        options=options,
    )
    db.add(agent)
    await db.flush()
    await _new_version(
        db,
        agent,
        p,
        prompt=prompt,
        model=model_row,
        max_iterations=iterations,
        timeout_s=timeout,
        output_schema=out_schema,
    )
    await db.commit()
    return RedirectResponse(f"/ui/agents/{agent.id}", status_code=303)


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
async def agent_detail(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        return RedirectResponse("/ui", status_code=303)
    role = await _team_role(db, p, agent.team_id)
    if role is None:
        return RedirectResponse("/ui", status_code=303)
    tenant = await db.get(Tenant, agent.tenant_id)
    tenants = await _visible_tenants(db, p)
    team = await db.get(Team, agent.team_id)

    versions_rows = (
        await db.execute(
            select(AgentVersion, Model.model_string)
            .join(Model, AgentVersion.model_id == Model.id, isouter=True)
            .where(AgentVersion.agent_id == agent.id)
            .order_by(AgentVersion.version_no.desc())
        )
    ).all()
    alias_rows = list(
        await db.scalars(
            select(VersionAlias)
            .where(VersionAlias.agent_id == agent.id)
            .order_by(VersionAlias.alias)
        )
    )
    aliases_by_version: dict[uuid.UUID, list[str]] = {}
    for a in alias_rows:
        aliases_by_version.setdefault(a.agent_version_id, []).append(a.alias)

    versions = [
        {
            "id": v.id,
            "version_no": v.version_no,
            "prompt": v.prompt,
            "model_string": model_string or "?",
            "max_iterations": v.max_iterations,
            "timeout_s": v.timeout_s,
            "created_at": v.created_at,
            "aliases": aliases_by_version.get(v.id, []),
        }
        for v, model_string in versions_rows
    ]

    current_memory = await latest_memory(db, agent.id)
    pending_rows = list(
        await db.scalars(
            select(MemoryVersion)
            .where(MemoryVersion.agent_id == agent.id, MemoryVersion.status == "pending")
            .order_by(MemoryVersion.version_no)
        )
    )
    baseline_run = await db.scalar(
        select(EvalRun)
        .where(
            EvalRun.agent_id == agent.id,
            EvalRun.status == "completed",
            EvalRun.memory_version_id.is_(None),
        )
        .order_by(EvalRun.created_at.desc())
        .limit(1)
    )
    baseline = (
        float(baseline_run.pass_rate)
        if baseline_run and baseline_run.pass_rate is not None
        else None
    )
    pending_memory = []
    for mv in pending_rows:
        gate = await db.scalar(
            select(EvalRun)
            .where(EvalRun.memory_version_id == mv.id)
            .order_by(EvalRun.created_at.desc())
            .limit(1)
        )
        pending_memory.append({"version": mv, "eval_run": gate, "baseline": baseline})

    runs_rows = (
        await db.execute(
            select(EvalRun, AgentVersion.version_no)
            .join(AgentVersion, EvalRun.agent_version_id == AgentVersion.id)
            .where(EvalRun.agent_id == agent.id)
            .order_by(EvalRun.created_at.desc())
            .limit(10)
        )
    ).all()
    eval_runs = [
        {
            "id": r.id,
            "version_no": vno,
            "status": r.status,
            "pass_rate": float(r.pass_rate) if r.pass_rate is not None else None,
            "memory_version_id": r.memory_version_id,
            "created_at": r.created_at,
        }
        for r, vno in runs_rows
    ]
    case_rows = list(
        await db.scalars(
            select(EvalCase).where(EvalCase.agent_id == agent.id).order_by(EvalCase.name)
        )
    )
    # Spell the checks out in the list: "equals risk_level" says a check exists,
    # not what it wants, and a case that has never run has no results to read.
    eval_cases = [
        {
            "id": c.id,
            "name": c.name,
            "prompt": (c.input or {}).get("prompt", ""),
            "checks": [_check_label(check) for check in c.checks],
        }
        for c in case_rows
    ]
    recent_jobs = list(
        await db.scalars(
            select(Job).where(Job.agent_id == agent.id).order_by(Job.created_at.desc()).limit(10)
        )
    )
    charts = await _activity_charts(db, Job.agent_id == agent.id, datetime.now(UTC))
    # Owner-only, matching who the API lets issue an agent-scoped key. Nothing
    # secret is on show — the plaintext exists only in the response that
    # created it — but the panel is all owner actions, so it hides whole.
    can_manage_keys = role == Role.OWNER
    invoke_keys = await _invoke_keys(db, agent.id) if can_manage_keys else []
    # Event sources list for any team member, matching what
    # api.v1.events.list_event_sources shows; creating and deleting stay owner
    # work, like the keys above. Provider credentials are owner-only whole:
    # which vendors a team pays for is not viewer business.
    event_sources = await _agent_event_sources(db, agent.id)
    agent_creds = await _provider_creds(db, KeyScope.AGENT, agent.id) if can_manage_keys else []
    # The whole memory trail, as GET /v1/agents/{id}/memory returns it. The
    # active document is rendered in full below it; this is what came before,
    # what was refused, and what a rollback would fall back to.
    memory_versions = list(
        await db.scalars(
            select(MemoryVersion)
            .where(MemoryVersion.agent_id == agent.id)
            .order_by(MemoryVersion.version_no.desc())
        )
    )

    return templates.TemplateResponse(
        request,
        "agent_detail.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=tenants,
            section="agents",
            agent=agent,
            team=team,
            versions=versions,
            spend=float(await spending.month_spend(db, agent.id)),
            spending_limit=float(agent.spending_limit) if agent.spending_limit else None,
            current_memory=current_memory,
            pending_memory=pending_memory,
            eval_runs=eval_runs,
            current_version_no=next(
                (v["version_no"] for v in versions if v["id"] == agent.current_version_id), None
            ),
            eval_cases=eval_cases,
            recent_jobs=recent_jobs,
            jobs_chart=json.dumps(charts["jobs_chart"]),
            tokens_chart=json.dumps(charts["tokens_chart"]),
            chart_days=CHART_DAYS,
            jobs_total=charts["jobs_total"],
            avg_tokens_per_job=charts["avg_tokens_per_job"],
            invoke_keys=invoke_keys,
            can_manage_keys=can_manage_keys,
            event_sources=event_sources,
            agent_creds=agent_creds,
            providers=PROVIDER_CHOICES,
            memory_versions=memory_versions,
            can_promote=role == Role.OWNER,
            # Deletable only while nothing has ever run on it, matching the
            # API's refusal — offering a button that always fails would be
            # worse than not offering one.
            can_delete=role == Role.OWNER and not recent_jobs,
            can_edit=role in (Role.OWNER, Role.EDITOR) and agent.archived_at is None,
            can_archive=role == Role.OWNER,
        ),
    )


async def _agent_form_page(
    db: AsyncSession, p: UserPrincipal, agent_id: uuid.UUID
) -> tuple[Agent | None, Role | None, RedirectResponse | None]:
    """Shared gate for the agent-scoped form pages and eval actions: visible,
    editor+, and not archived (a retired agent takes no new work, so nothing to
    fill in)."""
    agent = await db.get(Agent, agent_id)
    if agent is None:
        return None, None, RedirectResponse("/ui", status_code=303)
    role = await _team_role(db, p, agent.team_id)
    if role not in (Role.OWNER, Role.EDITOR) or agent.archived_at is not None:
        return None, None, RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    return agent, role, None


async def _render_edit_agent(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    agent, role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(
        request,
        "agent_edit.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            team=await db.get(Team, agent.team_id),
            can_govern=role == Role.OWNER,
            can_archive=role == Role.OWNER,
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/agents/{agent_id}/settings", response_class=HTMLResponse)
async def edit_agent_page(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_edit_agent(request, agent_id, db, p)


@router.post("/agents/{agent_id}/settings")
async def ui_update_agent(
    request: Request,
    agent_id: uuid.UUID,
    name: str = Form(""),
    description: str = Form(""),
    spending_limit: str = Form(""),
    delegation: str = Form("none"),
    memory: bool = Form(False),
    learning: bool = Form(False),
    memory_approval: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    """Edit name, description, spending limit and options. Mirrors
    PATCH /v1/agents/{id}: editors change the rest, owners change the
    governed options — and only when a governed value actually flips."""
    settings = {
        "name": name,
        "description": description,
        "spending_limit": spending_limit,
        "delegation": delegation,
        "memory": memory,
        "learning": learning,
        "memory_approval": memory_approval,
    }

    async def fail(message: str):
        return await _render_edit_agent(
            request, agent_id, db, p, error=message, form=settings, status_code=400
        )

    agent, role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect

    options = _options_from_form(delegation, memory, learning, memory_approval)
    if _governed_change(agent.options or {}, options) and role != Role.OWNER:
        return await fail("Memory, learning and approval are owner-managed.")

    name, limit, err = await _clean_agent_fields(
        db, agent.tenant_id, name, spending_limit, exclude=agent.id
    )
    if err:
        return await fail(err)

    agent.name = name
    agent.description = description.strip()
    agent.spending_limit = limit
    agent.options = options
    await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/archive")
async def ui_archive_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent and agent.archived_at is None and await _team_role(db, p, agent.team_id) == Role.OWNER:
        agent.archived_at = datetime.now(UTC)
        await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/delete")
async def ui_delete_agent(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        return RedirectResponse("/ui", status_code=303)
    if await _team_role(db, p, agent.team_id) != Role.OWNER:
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    tenant_id = agent.tenant_id
    # The same refusal api.v1.agents.delete_agent makes, for the same reason:
    # jobs.agent_id does not cascade, so this would come back from the database
    # as an IntegrityError rather than as something a person can act on. Once
    # an agent has run, archiving is what retiring it means — the trail stays.
    jobs = await db.scalar(select(func.count()).select_from(Job).where(Job.agent_id == agent.id))
    if jobs:
        _flash(
            request,
            f"{agent.name} has {jobs} job(s) and cannot be deleted — archive it instead.",
        )
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    await db.delete(agent)
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/agents", status_code=303)


@router.post("/agents/{agent_id}/restore")
async def ui_restore_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if (
        agent
        and agent.archived_at is not None
        and await _team_role(db, p, agent.team_id) == Role.OWNER
    ):
        agent.archived_at = None
        await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


# --- Test runs ---
#
# Submission goes through api.v1.jobs.create_job rather than building a Job
# here: archived-agent refusal, idempotency, the budget pre-flight and the
# enqueue all live in it, and a second implementation would drift from them.
# What the form deliberately does not offer is callback_url, files, links and
# user_ctx — each carries its own policy, and a test run is a prompt.


def _version_choices(versions: list[dict], current_version_no: int | None) -> list[dict]:
    """Pin targets for the run form: current, then each version, then aliases."""
    choices = [{"value": "current", "label": f"current (v{current_version_no})"}]
    for v in versions:
        choices.append({"value": f"v:{v['version_no']}", "label": f"v{v['version_no']}"})
        for alias in v["aliases"]:
            choices.append({"value": f"a:{alias}", "label": f"{alias} → v{v['version_no']}"})
    return choices


async def _agent_versions(db: AsyncSession, agent: Agent) -> list[dict]:
    rows = list(
        await db.scalars(
            select(AgentVersion)
            .where(AgentVersion.agent_id == agent.id)
            .order_by(AgentVersion.version_no.desc())
        )
    )
    aliases: dict[uuid.UUID, list[str]] = {}
    for a in await db.scalars(
        select(VersionAlias).where(VersionAlias.agent_id == agent.id).order_by(VersionAlias.alias)
    ):
        aliases.setdefault(a.agent_version_id, []).append(a.alias)
    return [{"version_no": v.version_no, "aliases": aliases.get(v.id, [])} for v in rows]


async def _render_run_agent(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    if agent.current_version_id is None:
        _flash(request, "This agent has no versions yet — create one before running it.")
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    versions = await _agent_versions(db, agent)
    current = await db.get(AgentVersion, agent.current_version_id)
    return templates.TemplateResponse(
        request,
        "job_new.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            choices=_version_choices(versions, current.version_no),
            input_schema=_pretty_json(current.input_schema),
            spend=float(await spending.month_spend(db, agent.id)),
            spending_limit=float(agent.spending_limit) if agent.spending_limit else None,
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/agents/{agent_id}/run", response_class=HTMLResponse)
async def run_agent_page(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_run_agent(request, agent_id, db, p)


@router.post("/agents/{agent_id}/run")
async def ui_run_agent(
    request: Request,
    agent_id: uuid.UUID,
    prompt: str = Form(""),
    pin: str = Form("current"),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    from sleeper_service.api.v1.jobs import create_job

    form = {"prompt": prompt, "pin": pin}

    async def fail(message: str):
        return await _render_run_agent(
            request, agent_id, db, p, error=message, form=form, status_code=400
        )

    agent, role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect

    prompt = prompt.strip()
    if not prompt:
        return await fail("A prompt is required — it is the job's payload.")

    version = await _pinned_version(db, agent, pin)
    if version is None:
        return await fail("That version is no longer available — pick another.")

    job, _existed = await create_job(
        db,
        agent,
        version,
        context=JobContext(prompt=prompt).model_dump(mode="json"),
        # Same shape the API records for a user principal, so a job submitted
        # from the pages is not a different kind of row in the trail.
        auth_ctx={
            "type": "user",
            "user_id": str(p.user.id),
            "team_role": role,
            "tenant_id": str(agent.tenant_id),
            "team_id": str(agent.team_id),
            "agent_id": str(agent.id),
        },
    )
    # A job refused at the budget pre-flight still has a row and a reason, so
    # the job page is the right place to land either way.
    return RedirectResponse(f"/ui/jobs/{job.id}", status_code=303)


async def _pinned_version(db: AsyncSession, agent: Agent, pin: str) -> AgentVersion | None:
    """Resolve the run form's pin, mirroring api.v1.jobs._resolve_version."""
    if pin.startswith("v:"):
        return await db.scalar(
            select(AgentVersion).where(
                AgentVersion.agent_id == agent.id,
                AgentVersion.version_no == _safe_int(pin[2:]),
            )
        )
    if pin.startswith("a:"):
        row = await db.get(VersionAlias, (agent.id, pin[2:]))
        return await db.get(AgentVersion, row.agent_version_id) if row else None
    return await db.get(AgentVersion, agent.current_version_id)


def _safe_int(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        return -1


# --- Models registry ---
#
# Instance-level rather than per-tenant, and superuser-managed, so it hangs off
# /ui/models rather than a tenant path. Readable by any signed-in user, matching
# GET /v1/models: the version form's "register it under Models first" has to
# name somewhere its reader can actually look.


async def _render_models(
    request: Request,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    tenants = await _visible_tenants(db, p)
    return templates.TemplateResponse(
        request,
        "models.html",
        _ctx(
            request,
            p,
            tenant=next(iter(tenants), None),
            tenants=tenants,
            section="models",
            models=list(await db.scalars(select(Model).order_by(Model.provider, Model.name))),
            can_manage=p.user.is_superuser,
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/models", response_class=HTMLResponse)
async def models_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_models(request, db, p)


@router.post("/models")
async def ui_create_model(
    request: Request,
    provider: str = Form(""),
    name: str = Form(""),
    model_string: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {"provider": provider, "name": name, "model_string": model_string}

    async def fail(message: str):
        return await _render_models(request, db, p, error=message, form=form, status_code=400)

    if not p.user.is_superuser:
        return RedirectResponse("/ui/models", status_code=303)
    provider, name, model_string = provider.strip(), name.strip(), model_string.strip()
    if not provider or not name or not model_string:
        return await fail("Provider, name and model string are all required.")
    dup = await db.scalar(select(Model).where(Model.provider == provider, Model.name == name))
    if dup is not None:
        return await fail(f"{provider}/{name} is already registered.")
    # model_string is what a version stores and what the version form matches
    # on, so two rows sharing one would make the dropdown ambiguous.
    dup = await db.scalar(select(Model).where(Model.model_string == model_string))
    if dup is not None:
        return await fail(f"{model_string!r} is already registered as {dup.provider}/{dup.name}.")
    db.add(Model(provider=provider, name=name, model_string=model_string))
    await db.commit()
    return RedirectResponse("/ui/models", status_code=303)


@router.post("/models/{model_id}/delete")
async def ui_delete_model(
    request: Request,
    model_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    back = RedirectResponse("/ui/models", status_code=303)
    if not p.user.is_superuser:
        return back
    model = await db.get(Model, model_id)
    if model is None:
        return back
    # agent_versions.model_id is a plain FK, so the delete would otherwise come
    # back as an IntegrityError rather than something a person can act on.
    users = list(
        await db.scalars(
            select(Agent.name)
            .join(AgentVersion, AgentVersion.agent_id == Agent.id)
            .where(AgentVersion.model_id == model.id)
            .distinct()
            .order_by(Agent.name)
            .limit(4)
        )
    )
    if users:
        named = ", ".join(users[:3]) + (" and more" if len(users) > 3 else "")
        _flash(request, f"{model.model_string} is used by versions of {named}.")
        return back
    await db.delete(model)
    await db.commit()
    return back


# --- Connections: the data stores and MCP servers a version can be granted ---
#
# Both registries are tenant-level and tenant-admin managed, so they share one
# page. Listing is open to anyone with a team in the tenant, matching
# `_gate(admin=False)` on both API routers — an editor picking grants on the
# version form has to be able to see what exists.

# Blank grant rows offered on the version form.
GRANT_ROWS = 3
STORE_MODES = ("ro", "rw")
# Config key each store type cannot work without, mirroring
# api.v1.data_stores.REQUIRED_CONFIG.
STORE_REQUIRED_CONFIG = {
    "s3": "bucket",
    "azure_blob": "container",
    "gcs": "bucket",
    "box": "folder_id",
    "local": "base_path",
}
STORE_TYPES = tuple(sorted(STORE_REQUIRED_CONFIG))
MCP_TRANSPORTS = ("streamable_http", "sse", "stdio")
# Types whose SDK falls back to the host process's ambient cloud identity when
# no credential is given — see api.v1.data_stores.AMBIENT_CREDENTIAL_TYPES for
# why that is superuser-only.
AMBIENT_STORE_TYPES = {"s3", "azure_blob", "gcs"}


async def _tenant_admin_page(
    db: AsyncSession, p: UserPrincipal, tenant_id: uuid.UUID
) -> tuple[Tenant | None, bool, RedirectResponse | None]:
    """Visible tenant plus whether this user administers it. Non-admins still
    get the page — they need to read the registries to grant against them."""
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return None, False, tenant
    return tenant, await is_tenant_admin(db, p, tenant_id), None


async def _tenant_stores(db: AsyncSession, tenant_id: uuid.UUID) -> list[DataStore]:
    return list(
        await db.scalars(
            select(DataStore).where(DataStore.tenant_id == tenant_id).order_by(DataStore.name)
        )
    )


async def _tenant_mcp_servers(db: AsyncSession, tenant_id: uuid.UUID) -> list[McpServer]:
    return list(
        await db.scalars(
            select(McpServer).where(McpServer.tenant_id == tenant_id).order_by(McpServer.name)
        )
    )


@router.get("/t/{tenant_id}/connections", response_class=HTMLResponse)
async def connections_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(
        request,
        "connections.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="connections",
            stores=await _tenant_stores(db, tenant.id),
            servers=await _tenant_mcp_servers(db, tenant.id),
            can_manage=is_admin,
        ),
    )


async def _render_new_store(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    if not is_admin:
        return RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)
    return templates.TemplateResponse(
        request,
        "data_store_new.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="connections",
            store_types=STORE_TYPES,
            required_config=STORE_REQUIRED_CONFIG,
            is_superuser=p.user.is_superuser,
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/t/{tenant_id}/data-stores/new", response_class=HTMLResponse)
async def new_data_store_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_store(request, tenant_id, db, p)


@router.post("/t/{tenant_id}/data-stores")
async def ui_create_data_store(
    request: Request,
    tenant_id: uuid.UUID,
    name: str = Form(""),
    type: str = Form(""),
    config: str = Form(""),
    credentials: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {"name": name, "type": type, "config": config, "credentials": credentials}

    async def fail(message: str):
        return await _render_new_store(
            request, tenant_id, db, p, error=message, form=form, status_code=400
        )

    tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    if not is_admin:
        return RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)

    name = name.strip()
    if not name:
        return await fail("Name is required.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    if type not in STORE_REQUIRED_CONFIG:
        return await fail(f"Pick a store type — one of {', '.join(STORE_TYPES)}.")
    store_config, err = _form_json_object(config, "Config")
    if err:
        return await fail(err)
    store_config = store_config or {}
    required = STORE_REQUIRED_CONFIG[type]
    if required not in store_config:
        return await fail(f"A {type} store needs {required!r} in its config.")
    store_creds, err = _form_json_object(credentials, "Credentials")
    if err:
        return await fail(err)

    # Both gates are api.v1.data_stores', restated because the UI must not be
    # a way around them: a `local` store or a credential-less cloud store runs
    # on the platform's own identity rather than the tenant's.
    if type == "local" and not p.user.is_superuser:
        return await fail("Only instance superusers may register local data stores.")
    if type in AMBIENT_STORE_TYPES and not store_creds and not p.user.is_superuser:
        return await fail(
            f"A {type} store needs explicit credentials — without them it runs on the "
            "platform's own cloud identity, which only instance superusers may configure."
        )

    dup = await db.scalar(
        select(DataStore).where(DataStore.tenant_id == tenant.id, DataStore.name == name)
    )
    if dup is not None:
        return await fail(f"A data store named {name!r} already exists in this tenant.")

    db.add(
        DataStore(
            tenant_id=tenant.id,
            name=name,
            type=type,
            config=store_config,
            credentials_enc=encrypt(json.dumps(store_creds)) if store_creds else None,
        )
    )
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)


@router.post("/t/{tenant_id}/data-stores/{store_id}/delete")
async def ui_delete_data_store(
    request: Request,
    tenant_id: uuid.UUID,
    store_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    back = RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)
    if not is_admin:
        return back
    store = await db.get(DataStore, store_id)
    if store is None or store.tenant_id != tenant_id:
        return back
    # Grants name a store by name or id and resolve at run time, so deleting
    # one still granted turns every job on that version into a GrantError.
    holders = await _versions_granting(db, tenant_id, "data_store_grants", "store", store)
    if holders:
        _flash(
            request,
            f"{store.name} is still granted to {holders} — publish versions without it first.",
        )
        return back
    await db.delete(store)
    await db.commit()
    return back


async def _render_new_mcp_server(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    if not is_admin:
        return RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)
    return templates.TemplateResponse(
        request,
        "mcp_server_new.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="connections",
            transports=MCP_TRANSPORTS,
            is_superuser=p.user.is_superuser,
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/t/{tenant_id}/mcp-servers/new", response_class=HTMLResponse)
async def new_mcp_server_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_mcp_server(request, tenant_id, db, p)


@router.post("/t/{tenant_id}/mcp-servers")
async def ui_create_mcp_server(
    request: Request,
    tenant_id: uuid.UUID,
    name: str = Form(""),
    transport: str = Form(""),
    endpoint: str = Form(""),
    credentials: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {
        "name": name,
        "transport": transport,
        "endpoint": endpoint,
        "credentials": credentials,
    }

    async def fail(message: str):
        return await _render_new_mcp_server(
            request, tenant_id, db, p, error=message, form=form, status_code=400
        )

    tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    if not is_admin:
        return RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)

    name = name.strip()
    endpoint = endpoint.strip()
    if not name:
        return await fail("Name is required.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    if transport not in MCP_TRANSPORTS:
        return await fail(f"Pick a transport — one of {', '.join(MCP_TRANSPORTS)}.")
    if not endpoint:
        return await fail(
            "Command line is required." if transport == "stdio" else "Endpoint URL is required."
        )
    if transport == "stdio" and not p.user.is_superuser:
        return await fail("Only instance superusers may register stdio MCP servers.")
    if transport != "stdio":
        # The worker connects to this on every granted job, so it clears the
        # same address policy as a callback URL (audit 5). Checked again at
        # connect time in runtime/toolsets.
        try:
            validate_mcp_url(endpoint)
        except OutboundUrlError as e:
            return await fail(str(e))
    server_creds, err = _form_json_object(credentials, "Credentials")
    if err:
        return await fail(err)

    dup = await db.scalar(
        select(McpServer).where(McpServer.tenant_id == tenant.id, McpServer.name == name)
    )
    if dup is not None:
        return await fail(f"An MCP server named {name!r} already exists in this tenant.")

    db.add(
        McpServer(
            tenant_id=tenant.id,
            name=name,
            endpoint=endpoint,
            transport=transport,
            credentials_enc=encrypt(json.dumps(server_creds)) if server_creds else None,
        )
    )
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)


@router.post("/t/{tenant_id}/mcp-servers/{server_id}/delete")
async def ui_delete_mcp_server(
    request: Request,
    tenant_id: uuid.UUID,
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _tenant, is_admin, redirect = await _tenant_admin_page(db, p, tenant_id)
    if redirect is not None:
        return redirect
    back = RedirectResponse(f"/ui/t/{tenant_id}/connections", status_code=303)
    if not is_admin:
        return back
    server = await db.get(McpServer, server_id)
    if server is None or server.tenant_id != tenant_id:
        return back
    holders = await _versions_granting(db, tenant_id, "tool_grants", "server", server)
    if holders:
        _flash(
            request,
            f"{server.name} is still granted to {holders} — publish versions without it first.",
        )
        return back
    await db.delete(server)
    await db.commit()
    return back


async def _versions_granting(
    db: AsyncSession, tenant_id: uuid.UUID, column: str, key: str, row
) -> str:
    """Agents whose *current* version still grants this store/server, named for
    an error message; empty string if none.

    Only current versions count. Old versions keep their grants forever — they
    are immutable — so checking every version would make a registry entry
    undeletable after one job, while a dangling grant on a version nothing
    dispatches to cannot break a run.
    """
    stmt = (
        select(Agent.name, getattr(AgentVersion, column))
        .join(AgentVersion, Agent.current_version_id == AgentVersion.id)
        .where(Agent.tenant_id == tenant_id, Agent.archived_at.is_(None))
        .order_by(Agent.name)
    )
    names = [
        agent_name
        for agent_name, grants in (await db.execute(stmt)).all()
        for g in (grants or [])
        if isinstance(g, dict) and str(g.get(key, "")) in (row.name, str(row.id))
    ]
    unique = list(dict.fromkeys(names))
    if not unique:
        return ""
    if len(unique) > 3:
        return f"{', '.join(unique[:3])} and {len(unique) - 3} more"
    return ", ".join(unique)


# --- Invoke keys ---
#
# Agent-scoped data-plane keys: those are what make an agent built in the UI
# actually callable. The wider tenant- and team-scoped keys are issued where
# that scope is administered — see the invoke-key routes further down.


async def _key_admin_page(
    db: AsyncSession, p: UserPrincipal, agent_id: uuid.UUID
) -> tuple[Agent | None, RedirectResponse | None]:
    """Gate for the invoke-key pages, mirroring api_keys._require_scope_admin
    at agent scope: owner of the agent's team, where editor is not enough — a
    key outlives the session that made it and carries spend.

    Unlike the other agent-scoped forms this stays open on an archived agent:
    retiring one is exactly when its keys want revoking. Issuing is blocked
    separately.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        return None, RedirectResponse("/ui", status_code=303)
    if await _team_role(db, p, agent.team_id) != Role.OWNER:
        return None, RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    return agent, None


async def _invoke_keys(db: AsyncSession, agent_id: uuid.UUID) -> list[ApiKey]:
    return list(
        await db.scalars(
            select(ApiKey)
            .where(
                ApiKey.kind == KeyKind.INVOKE,
                ApiKey.scope == KeyScope.AGENT,
                ApiKey.scope_id == agent_id,
            )
            .order_by(ApiKey.created_at.desc())
        )
    )


@router.get("/agents/{agent_id}/invoke-keys/new", response_class=HTMLResponse)
async def new_invoke_key_page(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    if agent.archived_at is not None:
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    return templates.TemplateResponse(
        request,
        "invoke_key_new.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            form={},
        ),
    )


@router.post("/agents/{agent_id}/invoke-keys")
async def ui_create_invoke_key(
    request: Request,
    agent_id: uuid.UUID,
    name: str = Form(""),
    rate_limit: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    if agent.archived_at is not None:
        _flash(request, "This agent is archived — restore it before issuing a key.")
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)

    async def fail(message: str):
        return templates.TemplateResponse(
            request,
            "invoke_key_new.html",
            _ctx(
                request,
                p,
                tenant=await db.get(Tenant, agent.tenant_id),
                tenants=await _visible_tenants(db, p),
                section="agents",
                agent=agent,
                error=message,
                form={"name": name, "rate_limit": rate_limit},
            ),
            status_code=400,
        )

    name = name.strip()
    if not name:
        return await fail("Give the key a name — it is the only way to tell keys apart later.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    limit: int | None = None
    if rate_limit.strip():
        # Mirrors InvokeKeyCreate.rate_limit (ge=1); the upper bound is the UI's
        # own, since a limit past it is indistinguishable from no limit.
        limit, err = _form_int(rate_limit.strip(), 0, 1, 100000, "Rate limit")
        if err:
            return await fail(err)

    plaintext, key_hash = generate_key(KeyKind.INVOKE)
    key = ApiKey(
        kind=KeyKind.INVOKE,
        scope=KeyScope.AGENT,
        scope_id=agent.id,
        key_hash=key_hash,
        name=name,
        rate_limit=limit,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    # Rendered straight into this response rather than redirected through the
    # session: the session cookie is signed, not encrypted, so flashing the
    # secret would park a live data-plane credential in the browser's cookie
    # jar and every Set-Cookie header along the way.
    return templates.TemplateResponse(
        request,
        "invoke_key_created.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            key=key,
            plaintext=plaintext,
            base_url=get_settings().public_base_url.rstrip("/"),
        ),
        status_code=201,
    )


@router.post("/agents/{agent_id}/invoke-keys/{key_id}/revoke")
async def ui_revoke_invoke_key(
    agent_id: uuid.UUID,
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    key = await db.get(ApiKey, key_id)
    if (
        key is not None
        and key.kind == KeyKind.INVOKE
        and key.scope == KeyScope.AGENT
        and key.scope_id == agent_id
        and key.revoked_at is None
    ):
        key.revoked_at = datetime.now(UTC)
        await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


async def _render_new_version(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect

    form = form or {}
    # Prefilled from the current version, so iterating on a prompt is an edit
    # rather than a retype.
    current = (
        await db.get(AgentVersion, agent.current_version_id) if agent.current_version_id else None
    )
    current_model = (
        await db.scalar(select(Model.model_string).where(Model.id == current.model_id))
        if current is not None and current.model_id is not None
        else None
    )
    stores = [row.name for row in await _tenant_stores(db, agent.tenant_id)]
    servers = [row.name for row in await _tenant_mcp_servers(db, agent.tenant_id)]
    store_rows = _grant_rows(
        form.get("store_grant_rows") or (current.data_store_grants if current else None),
        ("store", "prefix", "mode"),
        GRANT_ROWS,
    )
    tool_rows = _grant_rows(
        form.get("tool_grant_rows") or (current.tool_grants if current else None),
        ("server", "tools"),
        GRANT_ROWS,
    )
    return templates.TemplateResponse(
        request,
        "version_new.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            models=await _model_strings(db),
            current_model=current_model or "",
            current_prompt=current.prompt if current else "",
            current_iters=current.max_iterations if current else 10,
            current_timeout=current.timeout_s if current else 300,
            current_output_schema=_pretty_json(current.output_schema if current else None),
            current_input_schema=_pretty_json(current.input_schema if current else None),
            current_params=_pretty_json(current.params if current else None),
            stores=stores,
            servers=servers,
            store_modes=STORE_MODES,
            store_rows=store_rows,
            tool_rows=tool_rows,
            # An empty registry normally means "nothing to grant", but a grant
            # left over from the API — or from a store since deleted — still
            # has to be editable, or saving would drop it without saying so.
            show_store_grid=bool(stores) or any(row[0] for row in store_rows),
            show_tool_grid=bool(servers) or any(row[0] for row in tool_rows),
            next_version_no=(current.version_no + 1) if current else 1,
            error=error,
            form=form,
        ),
        status_code=status_code,
    )


@router.get("/agents/{agent_id}/versions/new", response_class=HTMLResponse)
async def new_version_page(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_version(request, agent_id, db, p)


@router.post("/agents/{agent_id}/versions")
async def ui_create_version(
    request: Request,
    agent_id: uuid.UUID,
    model: str = Form(""),
    prompt: str = Form(""),
    max_iterations: str = Form("10"),
    timeout_s: str = Form("300"),
    output_schema: str = Form(""),
    input_schema: str = Form(""),
    params: str = Form(""),
    grant_store: list[str] = Form(default_factory=list),
    grant_prefix: list[str] = Form(default_factory=list),
    grant_mode: list[str] = Form(default_factory=list),
    grant_server: list[str] = Form(default_factory=list),
    grant_tools: list[str] = Form(default_factory=list),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    store_grants = _store_grants_from_form(grant_store, grant_prefix, grant_mode)
    tool_grants = _tool_grants_from_form(grant_server, grant_tools)
    form = {
        "model": model,
        "prompt": prompt,
        "max_iterations": max_iterations,
        "timeout_s": timeout_s,
        "output_schema": output_schema,
        "input_schema": input_schema,
        "params": params,
        # Re-rendered as rows rather than raw fields, so a rejected submission
        # comes back with the grants the user picked still in place.
        "store_grant_rows": store_grants,
        "tool_grant_rows": tool_grants,
    }

    async def fail(message: str):
        return await _render_new_version(
            request, agent_id, db, p, error=message, form=form, status_code=400
        )

    agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect

    prompt = prompt.strip()
    if not prompt:
        return await fail("Prompt is required.")
    iterations, err = _form_int(max_iterations, 10, 1, 100, "Max iterations")
    if err:
        return await fail(err)
    timeout, err = _form_int(timeout_s, 300, 1, 3600, "Timeout")
    if err:
        return await fail(err)
    out_schema, err = _form_json_object(output_schema, "Output schema", as_schema=True)
    if err:
        return await fail(err)
    in_schema, err = _form_json_object(input_schema, "Input schema", as_schema=True)
    if err:
        return await fail(err)
    model_params, err = _form_json_object(params, "Model params")
    if err:
        return await fail(err)
    model_row = await db.scalar(select(Model).where(Model.model_string == model))
    if model_row is None:
        return await fail(f"Unknown model {model!r} — register it under Models first.")

    # A grant naming something the tenant does not have is a GrantError on
    # every job the version runs, so it is refused here rather than at dispatch.
    known_stores = {s.name for s in await _tenant_stores(db, agent.tenant_id)}
    for g in store_grants:
        if g["store"] not in known_stores:
            return await fail(f"No data store named {g['store']!r} in this tenant.")
    known_servers = {m.name for m in await _tenant_mcp_servers(db, agent.tenant_id)}
    for g in tool_grants:
        if g["server"] not in known_servers:
            return await fail(f"No MCP server named {g['server']!r} in this tenant.")
    if len({g["store"] for g in store_grants}) != len(store_grants):
        return await fail("Each data store may be granted once — merge the duplicate rows.")
    if len({g["server"] for g in tool_grants}) != len(tool_grants):
        return await fail("Each MCP server may be granted once — merge the duplicate rows.")

    await _new_version(
        db,
        agent,
        p,
        prompt=prompt,
        model=model_row,
        max_iterations=iterations,
        timeout_s=timeout,
        params=model_params,
        input_schema=in_schema,
        output_schema=out_schema,
        tool_grants=tool_grants,
        data_store_grants=store_grants,
    )
    await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.get("/agents/{agent_id}/versions/{version_no}", response_class=HTMLResponse)
async def version_detail(
    request: Request,
    agent_id: uuid.UUID,
    version_no: int,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    """The whole of a version: a truncated prompt in a table is enough to tell
    two versions apart, not enough to know what a job or an eval run ran."""
    agent = await db.get(Agent, agent_id)
    if agent is None or await _team_role(db, p, agent.team_id) is None:
        return RedirectResponse("/ui", status_code=303)
    version = await db.scalar(
        select(AgentVersion).where(
            AgentVersion.agent_id == agent.id, AgentVersion.version_no == version_no
        )
    )
    if version is None:
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)

    model_string = (
        await db.scalar(select(Model.model_string).where(Model.id == version.model_id))
        if version.model_id
        else None
    )
    author = (
        await db.scalar(select(User.email).where(User.id == version.created_by))
        if version.created_by
        else None
    )
    aliases = list(
        await db.scalars(
            select(VersionAlias.alias)
            .where(VersionAlias.agent_version_id == version.id)
            .order_by(VersionAlias.alias)
        )
    )
    return templates.TemplateResponse(
        request,
        "version_detail.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            version=version,
            model_string=model_string or "?",
            author=author,
            aliases=aliases,
            is_current=version.id == agent.current_version_id,
            output_schema=_pretty_json(version.output_schema),
            input_schema=_pretty_json(version.input_schema),
            params=_pretty_json(version.params),
        ),
    )


# --- Evals ---

# The grid offers the ops that fit three boxes; a code grader needs its source,
# so it goes through the JSON escape hatch beside the grid.
ROW_OPS = [*sorted(PATH_OPS), "is_valid"]


def _check_value(raw: str):
    """A value typed into the checks grid: JSON when it parses — numbers,
    [min, max], true — otherwise the literal string the editor typed."""
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _checks_from_form(
    ops: list[str], paths: list[str], values: list[str], extra: str
) -> tuple[list, str | None]:
    """Guided rows first, then the raw-JSON checks appended. Blank rows are
    skipped, so the form can offer more rows than a case needs."""
    checks: list = []
    for op, path, value in zip(ops, paths, values, strict=False):
        op = op.strip()
        if not op:
            continue
        if op not in ROW_OPS:
            return [], f"Unknown check {op!r}."
        check: dict = {"op": op}
        if op in PATH_OPS:
            if not path.strip():
                return [], f"A {op} check needs a path into the output."
            check["path"] = path.strip()
            check["value"] = _check_value(value)
        checks.append(check)

    if extra.strip():
        try:
            parsed = json.loads(extra)
        except json.JSONDecodeError as e:
            return [], f"Extra checks are not valid JSON: {e}"
        if not isinstance(parsed, list) or not all(isinstance(c, dict) for c in parsed):
            return [], "Extra checks must be a JSON array of check objects."
        checks.extend(parsed)

    if not checks:
        return [], "At least one check is required."
    return checks, None


async def _render_new_eval_case(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect

    form = form or {}
    rows = list(
        zip(
            form.get("check_op", []),
            form.get("check_path", []),
            form.get("check_value", []),
            strict=False,
        )
    )
    rows += [("", "", "")] * max(0, CHECK_ROWS - len(rows))
    return templates.TemplateResponse(
        request,
        "eval_case_new.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            row_ops=ROW_OPS,
            rows=rows,
            error=error,
            form=form,
        ),
        status_code=status_code,
    )


@router.get("/agents/{agent_id}/eval-cases/new", response_class=HTMLResponse)
async def new_eval_case_page(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_eval_case(request, agent_id, db, p)


@router.post("/agents/{agent_id}/eval-cases")
async def ui_create_eval_case(
    request: Request,
    agent_id: uuid.UUID,
    name: str = Form(""),
    prompt: str = Form(""),
    check_op: list[str] = Form(default_factory=list),
    check_path: list[str] = Form(default_factory=list),
    check_value: list[str] = Form(default_factory=list),
    extra_checks: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {
        "name": name,
        "prompt": prompt,
        "check_op": check_op,
        "check_path": check_path,
        "check_value": check_value,
        "extra_checks": extra_checks,
    }

    async def fail(message: str):
        return await _render_new_eval_case(
            request, agent_id, db, p, error=message, form=form, status_code=400
        )

    agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect

    name = name.strip()
    if not name:
        return await fail("Name is required.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    if not prompt.strip():
        return await fail("A prompt is required — it is the job input the case runs.")

    checks, error = _checks_from_form(check_op, check_path, check_value, extra_checks)
    if error is not None:
        return await fail(error)
    # Same gate as the API: a code check is compiled in the sandbox, which
    # blocks, so keep it off the event loop.
    error = await anyio.to_thread.run_sync(validate_checks, checks)
    if error is not None:
        return await fail(error)

    if await db.scalar(
        select(EvalCase).where(EvalCase.agent_id == agent.id, EvalCase.name == name)
    ):
        return await fail(f"A case named {name!r} already exists for this agent.")

    db.add(
        EvalCase(
            agent_id=agent.id,
            name=name,
            input=JobContext(prompt=prompt.strip()).model_dump(mode="json"),
            checks=checks,
            created_by=p.user.id,
        )
    )
    await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.get("/agents/{agent_id}/eval-cases/{case_id}", response_class=HTMLResponse)
async def eval_case_detail(
    request: Request,
    agent_id: uuid.UUID,
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent is None or await _team_role(db, p, agent.team_id) is None:
        return RedirectResponse("/ui", status_code=303)
    case = await db.get(EvalCase, case_id)
    if case is None or case.agent_id != agent_id:
        # a run's results outlive the case they graded, so its link can dangle
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)

    author = (
        await db.scalar(select(User.email).where(User.id == case.created_by))
        if case.created_by
        else None
    )
    checks = [{"label": _check_label(check), "code": check.get("code")} for check in case.checks]
    return templates.TemplateResponse(
        request,
        "eval_case.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            case=case,
            prompt=(case.input or {}).get("prompt", ""),
            checks=checks,
            author=author,
        ),
    )


@router.post("/agents/{agent_id}/eval-cases/{case_id}/delete")
async def ui_delete_eval_case(
    agent_id: uuid.UUID,
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    case = await db.get(EvalCase, case_id)
    if case is not None and case.agent_id == agent_id:
        await db.delete(case)
        await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/eval-runs")
async def ui_start_eval_run(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    from sleeper_service.queue import get_pool

    agent, _role, redirect = await _agent_form_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    back = RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)

    # Mirrors POST /v1/agents/{id}/eval-runs, which refuses each of these
    # rather than queueing a run that could only fail.
    if agent.current_version_id is None:
        _flash(request, "This agent has no versions yet — create one before running an eval.")
        return back
    has_case = await db.scalar(select(EvalCase.id).where(EvalCase.agent_id == agent.id).limit(1))
    if has_case is None:
        _flash(request, "Add an eval case before starting a run.")
        return back
    spend = await spending.budget_exhausted(db, agent)
    if spend is not None:
        _flash(request, f"Monthly spend {spend} has reached the limit {agent.spending_limit}.")
        return back

    run = EvalRun(
        agent_id=agent.id,
        agent_version_id=agent.current_version_id,
        created_by=p.user.id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    pool = await get_pool()
    await pool.enqueue_job("run_eval", str(run.id))
    return back


def _check_label(check: dict) -> str:
    """One line naming what a check asserts, for the run detail table. A code
    grader has no path or value to name — its source is shown instead."""
    op = check.get("op", "?")
    if op == "code":
        return f"code grader ({check.get('runner') or 'monty'})"
    path = check.get("path")
    if path is None:
        return op
    return f"{path} {op} {json.dumps(check.get('value'))}"


@router.get("/eval-runs/{run_id}", response_class=HTMLResponse)
async def eval_run_detail(
    request: Request,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    run = await db.get(EvalRun, run_id)
    if run is None:
        return RedirectResponse("/ui", status_code=303)
    agent = await db.get(Agent, run.agent_id)
    if await _team_role(db, p, agent.team_id) is None:
        return RedirectResponse("/ui", status_code=303)
    version = await db.get(AgentVersion, run.agent_version_id)
    memory_version = (
        await db.get(MemoryVersion, run.memory_version_id) if run.memory_version_id else None
    )

    # results are a snapshot taken when the run graded: a case edited or
    # deleted since does not change what this run saw.
    def _checks(result: dict) -> list[dict]:
        out = []
        for c in result.get("checks", []):
            check = c.get("check") or {}
            out.append({**c, "label": _check_label(check), "code": check.get("code")})
        return out

    cases = [{**r, "checks": _checks(r)} for r in run.results or []]

    return templates.TemplateResponse(
        request,
        "eval_run.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            run=run,
            version_no=version.version_no if version else None,
            memory_version=memory_version,
            pass_rate=float(run.pass_rate) if run.pass_rate is not None else None,
            cases=cases,
            passed_cases=sum(1 for c in cases if c.get("passed")),
        ),
    )


# --- Jobs ---


async def _render_tree(
    db: AsyncSession,
    job: Job,
    p: UserPrincipal,
    *,
    visited: set[uuid.UUID] | None = None,
    depth: int = 0,
) -> str:
    visited = visited or {job.id}
    if depth >= 50:
        return ""
    children = list(
        await db.scalars(select(Job).where(Job.parent_job_id == job.id).order_by(Job.created_at))
    )
    if not children:
        return ""
    parts = ["<ul>"]
    visible_count = 0
    for child in children:
        agent = await db.get(Agent, child.agent_id)
        if child.id in visited or agent is None or await _team_role(db, p, agent.team_id) is None:
            continue
        visible_count += 1
        visited.add(child.id)
        parts.append(
            f'<li><span class="badge {escape(child.status)}">{escape(child.status)}</span> '
            f"<strong>{escape(agent.name if agent else '?')}</strong> "
            f'<a class="mono" href="/ui/jobs/{child.id}">{str(child.id)[:8]}</a>'
            f"{await _render_tree(db, child, p, visited=visited, depth=depth + 1)}</li>"
        )
    parts.append("</ul>")
    return "".join(parts) if visible_count else ""


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail(
    request: Request,
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    job = await db.get(Job, job_id)
    if job is None:
        return RedirectResponse("/ui", status_code=303)
    agent = await db.get(Agent, job.agent_id)
    role = await _team_role(db, p, agent.team_id)
    if role is None:
        return RedirectResponse("/ui", status_code=303)
    tenant = await db.get(Tenant, agent.tenant_id)
    tenants = await _visible_tenants(db, p)
    version = await db.get(AgentVersion, job.agent_version_id)
    events = list(
        await db.scalars(select(JobEvent).where(JobEvent.job_id == job.id).order_by(JobEvent.id))
    )
    tree_html = await _render_tree(db, job, p)

    return templates.TemplateResponse(
        request,
        "job_detail.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=tenants,
            section="agents",
            job=job,
            agent=agent,
            version_no=version.version_no if version else "?",
            payload_json=json.dumps(job.payload, indent=2)[:4000],
            output_json=json.dumps(job.output, indent=2)[:4000] if job.output else None,
            events=events,
            tree_children=bool(tree_html),
            tree_html=tree_html,
            can_submit=role in (Role.OWNER, Role.EDITOR),
            feedback=await db.scalar(select(Feedback).where(Feedback.job_id == job.id)),
            # The API gates feedback on learning being on, since a vote with
            # nowhere to fold into is a vote thrown away.
            takes_feedback=learning_enabled(agent.options or {}),
        ),
    )


@router.post("/jobs/{job_id}/feedback")
async def ui_submit_feedback(
    request: Request,
    job_id: uuid.UUID,
    vote: str = Form(""),
    comment: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    """Record a vote on a result, feeding runtime/learning the same way the
    signed feedback URL does.

    No token here: that token exists so the party holding a callback URL can
    reply without a platform key. A signed-in user with an editor role on the
    agent's team is a stronger claim than holding it, so the session is the
    credential and the role is the gate.
    """
    from sleeper_service.queue import get_pool

    job = await db.get(Job, job_id)
    if job is None:
        return RedirectResponse("/ui", status_code=303)
    back = RedirectResponse(f"/ui/jobs/{job_id}", status_code=303)
    agent = await db.get(Agent, job.agent_id)
    if await _team_role(db, p, agent.team_id) not in (Role.OWNER, Role.EDITOR):
        return back
    if not learning_enabled(agent.options or {}):
        _flash(request, f"{agent.name} does not have learning switched on.")
        return back
    if vote not in ("1", "-1"):
        _flash(request, "Pick helpful or unhelpful.")
        return back
    if await db.scalar(select(Feedback).where(Feedback.job_id == job.id)) is not None:
        _flash(request, "This job already has feedback — one vote per job.")
        return back

    fb = Feedback(job_id=job.id, vote=int(vote), comment=comment.strip()[:2000] or None)
    db.add(fb)
    await db.commit()
    await db.refresh(fb)
    pool = await get_pool()
    await pool.enqueue_job("fold_feedback", str(fb.id))
    return back


# --- Provider credentials ---
#
# The same three-field form at three scopes, because that is what the API is:
# tenant creds on the settings page, team creds on the team page, agent creds
# on the agent page. Runtime resolution walks agent → team → tenant → process
# environment, so where a credential is set decides which vendor bill the
# spend lands on — which is why the form is repeated per scope rather than
# collected in one place with a scope picker.
#
# Nothing here is ever read back: the API never returns a credential, and the
# UI cannot either, so an existing entry offers replace and delete only.

# 'test' is excluded: the test provider is the in-process fake, and a key for
# it would be a credential for nothing. A row the API wrote under some other
# provider name still lists and still deletes — the select gates writes, not
# what is already there.
PROVIDER_CHOICES = tuple(sorted(SUPPORTED_PROVIDERS - {"test"}))


async def _provider_creds(
    db: AsyncSession, scope: KeyScope, scope_id: uuid.UUID
) -> list[ProviderCred]:
    return list(
        await db.scalars(
            select(ProviderCred)
            .where(ProviderCred.scope == scope, ProviderCred.scope_id == scope_id)
            .order_by(ProviderCred.provider)
        )
    )


async def _set_provider_cred(
    db: AsyncSession, scope: KeyScope, scope_id: uuid.UUID, provider: str, api_key: str
) -> str | None:
    """Upsert one credential, mirroring provider_creds._set. Error message or None."""
    provider = provider.strip().lower()
    if provider not in PROVIDER_CHOICES:
        return f"Pick a provider — one of {', '.join(PROVIDER_CHOICES)}."
    api_key = api_key.strip()
    if not api_key:
        return "The API key is required."
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == scope,
            ProviderCred.scope_id == scope_id,
            ProviderCred.provider == provider,
        )
    )
    if cred is None:
        db.add(
            ProviderCred(
                scope=scope,
                scope_id=scope_id,
                provider=provider,
                credentials_enc=encrypt(api_key),
            )
        )
    else:
        cred.credentials_enc = encrypt(api_key)
    await db.commit()
    return None


async def _delete_provider_cred(
    db: AsyncSession, scope: KeyScope, scope_id: uuid.UUID, provider: str
) -> None:
    """Delete by name rather than id: the name is what resolution looks up, and
    scope+scope_id+provider is unique, so it cannot address another scope's row."""
    cred = await db.scalar(
        select(ProviderCred).where(
            ProviderCred.scope == scope,
            ProviderCred.scope_id == scope_id,
            ProviderCred.provider == provider.strip().lower(),
        )
    )
    if cred is not None:
        await db.delete(cred)
        await db.commit()


# --- Tenant settings: the admin console ---
#
# Everything on this page is tenant-admin work against a tenant-scoped API
# surface: the tenant's own row, the provider credentials billed to it, and
# the IdP its people sign in through. Unlike Connections there is no reader
# half — none of it is something an editor picks from when publishing — so
# the page is admin-only whole rather than admin-only in its buttons.


async def _tenant_admin_or_redirect(
    db: AsyncSession, p: UserPrincipal, tenant_id: uuid.UUID
) -> tuple[Tenant | None, RedirectResponse | None]:
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return None, tenant
    if not await is_tenant_admin(db, p, tenant_id):
        return None, RedirectResponse(f"/ui/t/{tenant_id}", status_code=303)
    return tenant, None


async def _render_settings(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    created_key: ApiKey | None = None,
    plaintext: str | None = None,
    status_code: int = 200,
):
    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect
    oidc = await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant.id))
    defaults = {
        "system_prompt": tenant.system_prompt,
        "settings": _pretty_json(tenant.settings),
        "issuer": oidc.issuer if oidc else "",
        "client_id": oidc.client_id if oidc else "",
        "scopes": oidc.scopes if oidc else "openid email profile",
    }
    return templates.TemplateResponse(
        request,
        "settings.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="settings",
            creds=await _provider_creds(db, KeyScope.TENANT, tenant.id),
            providers=PROVIDER_CHOICES,
            invoke_keys=await _scoped_invoke_keys(db, KeyScope.TENANT, tenant.id),
            created_key=created_key,
            plaintext=plaintext,
            oidc=oidc,
            # What the IdP must have registered as the redirect URI — it is
            # built from the same route the callback is served on, so it
            # cannot drift from where the flow actually returns.
            redirect_uri=str(request.url_for("oidc_callback", tenant_id=tenant.id)),
            # The form re-renders with what was typed on an error and with the
            # stored values otherwise, so a rejected edit is corrected rather
            # than retyped.
            form={**defaults, **(form or {})},
            error=error,
        ),
        status_code=status_code,
    )


@router.get("/t/{tenant_id}/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_settings(request, tenant_id, db, p)


@router.post("/t/{tenant_id}/settings")
async def ui_update_tenant(
    request: Request,
    tenant_id: uuid.UUID,
    system_prompt: str = Form(""),
    settings: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {"system_prompt": system_prompt, "settings": settings}

    async def fail(message: str):
        return await _render_settings(
            request, tenant_id, db, p, error=message, form=form, status_code=400
        )

    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect

    blob, err = _form_json_object(settings, "Settings")
    if err:
        return await fail(err)
    # A form posts whole state, so an emptied field means an emptied blob —
    # unlike TenantUpdate, where omitting the field means "leave it alone".
    # The textarea arrives prefilled with what is stored, so clearing it is a
    # deliberate act rather than an omission.
    blob = blob or {}
    error = validate_hooks_settings(blob) or validate_learning_settings(blob)
    if error is not None:
        return await fail(error)

    tenant.system_prompt = system_prompt.strip()
    tenant.settings = blob
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/settings", status_code=303)


@router.post("/t/{tenant_id}/provider-creds")
async def ui_set_tenant_provider_cred(
    request: Request,
    tenant_id: uuid.UUID,
    provider: str = Form(""),
    api_key: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect
    error = await _set_provider_cred(db, KeyScope.TENANT, tenant.id, provider, api_key)
    if error is not None:
        return await _render_settings(request, tenant_id, db, p, error=error, status_code=400)
    return RedirectResponse(f"/ui/t/{tenant_id}/settings", status_code=303)


@router.post("/t/{tenant_id}/provider-creds/delete")
async def ui_delete_tenant_provider_cred(
    tenant_id: uuid.UUID,
    provider: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect
    await _delete_provider_cred(db, KeyScope.TENANT, tenant.id, provider)
    return RedirectResponse(f"/ui/t/{tenant_id}/settings", status_code=303)


@router.post("/t/{tenant_id}/oidc")
async def ui_set_oidc(
    request: Request,
    tenant_id: uuid.UUID,
    issuer: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    scopes: str = Form("openid email profile"),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {"issuer": issuer, "client_id": client_id, "scopes": scopes}

    async def fail(message: str):
        return await _render_settings(
            request, tenant_id, db, p, error=message, form=form, status_code=400
        )

    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect

    issuer, client_id = issuer.strip().rstrip("/"), client_id.strip()
    scopes = " ".join(scopes.split()) or "openid email profile"
    # Bounds are OidcConfigSet's; the UI must not accept what the API rejects.
    if not re.match(r"^https?://", issuer) or len(issuer) > 500:
        return await fail("The issuer must be an http(s) URL of 500 characters or fewer.")
    if not client_id or len(client_id) > 500:
        return await fail("A client ID is required, of 500 characters or fewer.")
    if not client_secret or len(client_secret) > 2000:
        return await fail(
            "The client secret is required, of 2000 characters or fewer. It is stored "
            "encrypted and never shown again, so changing anything here means entering it."
        )
    try:
        # The same gate as the API (audit-3 #2): the discovery document is
        # fetched server-side, so an issuer naming an internal address turns
        # the login flow into a probe of the platform's own network.
        validate_callback_url(
            issuer,
            allow_loopback=get_settings().oidc_allow_loopback_issuers,
            label="OIDC issuer",
        )
    except OutboundUrlError as e:
        return await fail(str(e))

    config = await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant.id))
    if config is None:
        config = OidcConfig(tenant_id=tenant.id)
        db.add(config)
    config.issuer = issuer
    config.client_id = client_id
    config.client_secret_enc = encrypt(client_secret)
    config.scopes = scopes
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/settings", status_code=303)


@router.post("/t/{tenant_id}/oidc/delete")
async def ui_delete_oidc(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect
    config = await db.scalar(select(OidcConfig).where(OidcConfig.tenant_id == tenant.id))
    if config is not None:
        await db.delete(config)
        await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/settings", status_code=303)


# --- Files ---
#
# Tenant-scoped like the API surface: any member of any team in the tenant may
# upload and read, which is exactly what _visible_tenants already establishes
# for a user principal. Jobs reference a file by id, so the list exists to make
# an id findable — uploading one and then having no way to name it would leave
# the gap the upload was closing.


async def _tenant_files(db: AsyncSession, tenant_id: uuid.UUID) -> list[dict]:
    rows = list(
        await db.scalars(
            select(File).where(File.tenant_id == tenant_id).order_by(File.created_at.desc())
        )
    )
    return [
        {
            "id": f.id,
            "name": f.object_key.rsplit("/", 1)[-1],
            "size": f.size,
            "content_type": f.content_type,
            "created_at": f.created_at,
            "expires_at": f.expires_at,
        }
        for f in rows
    ]


async def _render_files(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    status_code: int = 200,
):
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant
    return templates.TemplateResponse(
        request,
        "files.html",
        _ctx(
            request,
            p,
            tenant=tenant,
            tenants=await _visible_tenants(db, p),
            section="files",
            files=await _tenant_files(db, tenant.id),
            max_size_mb=MAX_FILE_SIZE // (1024 * 1024),
            error=error,
        ),
        status_code=status_code,
    )


@router.get("/t/{tenant_id}/files", response_class=HTMLResponse)
async def files_page(
    request: Request,
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_files(request, tenant_id, db, p)


@router.post("/t/{tenant_id}/files")
async def ui_upload_file(
    request: Request,
    tenant_id: uuid.UUID,
    file: UploadFile | None = None,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant = await _tenant_or_home(db, p, tenant_id)
    if isinstance(tenant, RedirectResponse):
        return tenant

    async def fail(message: str):
        return await _render_files(request, tenant_id, db, p, error=message, status_code=400)

    if file is None or not file.filename:
        return await fail("Choose a file to upload.")
    # Checked on the rolled size first, as api.v1.files does: read() pulls the
    # whole spooled body into memory, so a check that only runs afterwards
    # cannot keep an oversized upload from exhausting it (audit 5).
    if file.size is not None and file.size > MAX_FILE_SIZE:
        return await fail(f"That file is larger than the {MAX_FILE_SIZE // (1024 * 1024)} MiB cap.")
    data = await file.read()
    if len(data) > MAX_FILE_SIZE:
        return await fail(f"That file is larger than the {MAX_FILE_SIZE // (1024 * 1024)} MiB cap.")

    safe_name = Path(file.filename).name or "upload"
    file_id = uuid.uuid4()
    object_key = f"{tenant.id}/payload/{file_id}/{safe_name}"
    # The declared type is a security decision, not a display hint — see
    # api.v1.files.sniff_content_type. Reusing it rather than restating it
    # keeps the UI from being the way to label injection text as a PDF.
    content_type = sniff_content_type(data, file.content_type or "application/octet-stream")
    await storage.put_object(object_key, data, content_type)
    db.add(
        File(
            id=file_id,
            tenant_id=tenant.id,
            object_key=object_key,
            size=len(data),
            content_type=content_type,
            expires_at=file_expiry(tenant.settings or {}),
        )
    )
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant_id}/files", status_code=303)


@router.get("/files/{file_id}/content")
async def ui_download_file(
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    row = await db.get(File, file_id)
    if row is None:
        return RedirectResponse("/ui", status_code=303)
    if not p.user.is_superuser and not await visible_team_ids(db, p, row.tenant_id):
        return RedirectResponse("/ui", status_code=303)
    data = await storage.get_object(row.object_key)
    # Always a download, never a render. These bytes are uploaded by whoever
    # can reach the tenant and would otherwise be served from the same origin
    # as the session cookie that authorises this page: an HTML upload rendered
    # inline could act as the viewer against /ui. The API's own download has no
    # cookie to steal; this one does.
    return Response(
        content=data,
        media_type=row.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{row.object_key.rsplit("/", 1)[-1]}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# --- Users and API keys ---
#
# Creating a user is superuser work (api.v1.users.create_user), and until now
# it was the one thing that had to happen by curl before anything else could:
# adding someone to a team was already in the UI, but only for people who
# already existed. Rotating your *own* key needs no superuser, matching the
# API's `user_id != principal.user.id and not is_superuser` check, so it lives
# on its own page every signed-in user can reach.


async def _user_keys(db: AsyncSession, user_id: uuid.UUID) -> list[ApiKey]:
    return list(
        await db.scalars(
            select(ApiKey)
            .where(ApiKey.kind == KeyKind.USER, ApiKey.user_id == user_id)
            .order_by(ApiKey.created_at.desc())
        )
    )


async def _issue_user_key(db: AsyncSession, user_id: uuid.UUID) -> tuple[ApiKey, str]:
    plaintext, key_hash = generate_key(KeyKind.USER)
    key = ApiKey(kind=KeyKind.USER, user_id=user_id, key_hash=key_hash)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key, plaintext


async def _revoke_key(db: AsyncSession, key_id: uuid.UUID, user_id: uuid.UUID) -> None:
    key = await db.get(ApiKey, key_id)
    if (
        key is not None
        and key.kind == KeyKind.USER
        and key.user_id == user_id
        and key.revoked_at is None
    ):
        key.revoked_at = datetime.now(UTC)
        await db.commit()


async def _render_account(
    request: Request,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    plaintext: str | None = None,
    status_code: int = 200,
):
    tenants = await _visible_tenants(db, p)
    return templates.TemplateResponse(
        request,
        "account.html",
        _ctx(
            request,
            p,
            tenant=next(iter(tenants), None),
            tenants=tenants,
            section="account",
            keys=await _user_keys(db, p.user.id),
            plaintext=plaintext,
        ),
        status_code=status_code,
    )


@router.get("/account", response_class=HTMLResponse)
async def account_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_account(request, db, p)


@router.post("/account/keys")
async def ui_issue_own_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _key, plaintext = await _issue_user_key(db, p.user.id)
    # Rendered into this response rather than flashed through the session, for
    # the reason invoke keys are: the session cookie is signed but not
    # encrypted, so a flash parks a live credential in the cookie jar.
    return await _render_account(request, db, p, plaintext=plaintext, status_code=201)


@router.post("/account/keys/{key_id}/revoke")
async def ui_revoke_own_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    await _revoke_key(db, key_id, p.user.id)
    return RedirectResponse("/ui/account", status_code=303)


async def _render_users(
    request: Request,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    created: User | None = None,
    plaintext: str | None = None,
    status_code: int = 200,
):
    tenants = await _visible_tenants(db, p)
    rows = list(await db.scalars(select(User).order_by(User.email)))
    active = dict(
        (
            await db.execute(
                select(ApiKey.user_id, func.count())
                .where(ApiKey.kind == KeyKind.USER, ApiKey.revoked_at.is_(None))
                .group_by(ApiKey.user_id)
            )
        ).all()
    )
    return templates.TemplateResponse(
        request,
        "users.html",
        _ctx(
            request,
            p,
            tenant=next(iter(tenants), None),
            tenants=tenants,
            section="users",
            # Not "keys": Jinja resolves a dict's .keys to the method
            # before the item, so the count would render as a bound method.
            users=[{"user": u, "key_count": active.get(u.id, 0)} for u in rows],
            created=created,
            plaintext=plaintext,
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui/account", status_code=303)
    return await _render_users(request, db, p)


@router.post("/users")
async def ui_create_user(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    is_superuser: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui/account", status_code=303)
    form = {"email": email, "is_superuser": is_superuser}

    async def fail(message: str):
        return await _render_users(request, db, p, error=message, form=form, status_code=400)

    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        return await fail("That does not look like an email address.")
    # UserCreate's min_length; the API hashes whatever it is given, so this is
    # the only place a floor can be enforced from the pages.
    if len(password) < 8:
        return await fail("The password must be at least 8 characters.")
    if await db.scalar(select(User).where(User.email == email)):
        return await fail(f"{email} is already registered.")

    user = User(email=email, password_hash=hash_password(password), is_superuser=is_superuser)
    db.add(user)
    await db.flush()
    plaintext, key_hash = generate_key(KeyKind.USER)
    db.add(ApiKey(kind=KeyKind.USER, user_id=user.id, key_hash=key_hash, name="initial"))
    await db.commit()
    await db.refresh(user)
    # Born with a key, as POST /v1/users does — a user who cannot call the API
    # until someone mints one separately is half-created.
    return await _render_users(request, db, p, created=user, plaintext=plaintext, status_code=201)


async def _render_user_keys(
    request: Request,
    db: AsyncSession,
    p: UserPrincipal,
    subject: User,
    *,
    plaintext: str | None = None,
    status_code: int = 200,
):
    tenants = await _visible_tenants(db, p)
    return templates.TemplateResponse(
        request,
        "user_keys.html",
        _ctx(
            request,
            p,
            tenant=next(iter(tenants), None),
            tenants=tenants,
            section="users",
            subject=subject,
            keys=await _user_keys(db, subject.id),
            plaintext=plaintext,
        ),
        status_code=status_code,
    )


@router.get("/users/{user_id}/keys", response_class=HTMLResponse)
async def user_keys_page(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    # The page that makes DELETE /v1/users/{id}/keys/{key_id} reachable without
    # curl. The list page deliberately shows a count rather than rows — from
    # there the question is "cut this person off" — so picking one key needs a
    # page whose subject is one person, where a row can be told apart by its
    # name, its id and when it was issued.
    if not p.user.is_superuser:
        return RedirectResponse("/ui/account", status_code=303)
    subject = await db.get(User, user_id)
    if subject is None:
        return RedirectResponse("/ui/users", status_code=303)
    return await _render_user_keys(request, db, p, subject)


@router.post("/users/{user_id}/keys")
async def ui_issue_user_key(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui/account", status_code=303)
    subject = await db.get(User, user_id)
    if subject is None:
        return RedirectResponse("/ui/users", status_code=303)
    _key, plaintext = await _issue_user_key(db, subject.id)
    # Lands on the keys page rather than back on the list: the secret is
    # readable exactly once, and the page it renders into should be the one
    # that also shows what this person already holds.
    return await _render_user_keys(request, db, p, subject, plaintext=plaintext, status_code=201)


@router.post("/users/{user_id}/keys/{key_id}/revoke")
async def ui_revoke_user_key(
    user_id: uuid.UUID,
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui/account", status_code=303)
    # _revoke_key scopes by user_id as well as key_id, so a key id belonging to
    # someone else cannot be revoked by posting it under this user's path —
    # the same pairing DELETE /v1/users/{id}/keys/{key_id} enforces.
    await _revoke_key(db, key_id, user_id)
    return RedirectResponse(f"/ui/users/{user_id}/keys", status_code=303)


@router.post("/users/{user_id}/keys/revoke-all")
async def ui_revoke_user_keys(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui/account", status_code=303)
    # Kept alongside the per-key page above, because it answers a different
    # question: "cut this person off" should not be a row-by-row chore that
    # can be left half-done. Your own keys stay on /ui/account.
    now = datetime.now(UTC)
    for key in await _user_keys(db, user_id):
        if key.revoked_at is None:
            key.revoked_at = now
    await db.commit()
    return RedirectResponse("/ui/users", status_code=303)


# --- Notification channels ---
#
# Per team and owner-gated, matching api.v1.notif_channels._gate. The Apprise
# URL embeds its own credential (a Slack token, a webhook secret), so it is
# encrypted at rest and never returned — the list shows what a channel is
# subscribed to, not where it points.

NOTIF_EVENTS = ("dead_letter", "budget", "error_rate", "eval_regression", "callback_failed")


async def _team_channels(db: AsyncSession, team_id: uuid.UUID) -> list[NotifChannel]:
    return list(
        await db.scalars(
            select(NotifChannel)
            .where(NotifChannel.team_id == team_id)
            .order_by(NotifChannel.created_at)
        )
    )


@router.post("/teams/{team_id}/notif-channels")
async def ui_create_notif_channel(
    request: Request,
    team_id: uuid.UUID,
    apprise_url: str = Form(""),
    events: list[str] = Form(default=[]),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect

    async def fail(message: str):
        return await _render_team(request, team_id, db, p, error=message, status_code=400)

    apprise_url = apprise_url.strip()
    if not apprise_url:
        return await fail("An Apprise URL is required.")
    chosen = [e for e in events if e in NOTIF_EVENTS]
    if not chosen:
        return await fail("Pick at least one event — a channel subscribed to nothing is silent.")
    tenant = await db.get(Tenant, team.tenant_id)
    try:
        # Same validation as the API, and the same reason: the worker connects
        # to whatever this names, so it is an outbound destination like a
        # callback. Delivery re-checks it against a fresh resolution.
        validate_apprise_url(apprise_url, tenant.settings if tenant else {}, **notif_policy())
    except OutboundUrlError as e:
        return await fail(str(e))

    db.add(NotifChannel(team_id=team_id, apprise_url_enc=encrypt(apprise_url), events=chosen))
    await db.commit()
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


@router.post("/teams/{team_id}/notif-channels/{channel_id}/delete")
async def ui_delete_notif_channel(
    team_id: uuid.UUID,
    channel_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect
    channel = await db.get(NotifChannel, channel_id)
    if channel is not None and channel.team_id == team_id:
        await db.delete(channel)
        await db.commit()
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


@router.post("/teams/{team_id}/provider-creds")
async def ui_set_team_provider_cred(
    request: Request,
    team_id: uuid.UUID,
    provider: str = Form(""),
    api_key: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect
    error = await _set_provider_cred(db, KeyScope.TEAM, team.id, provider, api_key)
    if error is not None:
        return await _render_team(request, team_id, db, p, error=error, status_code=400)
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


@router.post("/teams/{team_id}/provider-creds/delete")
async def ui_delete_team_provider_cred(
    team_id: uuid.UUID,
    provider: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect
    await _delete_provider_cred(db, KeyScope.TEAM, team.id, provider)
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


# --- Event sources ---
#
# The API path is tenant-scoped, but a source targets exactly one agent and is
# managed by that agent's team owner, so the pages put it on the agent next to
# the invoke keys: both answer "how does something outside call this agent",
# one with a platform credential and one with a per-source secret.


async def _agent_event_sources(db: AsyncSession, agent_id: uuid.UUID) -> list[EventSource]:
    return list(
        await db.scalars(
            select(EventSource)
            .where(EventSource.target_agent_id == agent_id)
            .order_by(EventSource.name)
        )
    )


@router.get("/agents/{agent_id}/event-sources/new", response_class=HTMLResponse)
async def new_event_source_page(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    return await _render_new_event_source(request, agent_id, db, p)


async def _render_new_event_source(
    request: Request,
    agent_id: uuid.UUID,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    if agent.archived_at is not None:
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    return templates.TemplateResponse(
        request,
        "event_source_new.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            error=error,
            form=form or {"payload_template": _pretty_json({"prompt": "{{body}}"})},
        ),
        status_code=status_code,
    )


@router.post("/agents/{agent_id}/event-sources")
async def ui_create_event_source(
    request: Request,
    agent_id: uuid.UUID,
    name: str = Form(""),
    payload_template: str = Form(""),
    dedup_key_path: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {
        "name": name,
        "payload_template": payload_template,
        "dedup_key_path": dedup_key_path,
    }

    async def fail(message: str):
        return await _render_new_event_source(
            request, agent_id, db, p, error=message, form=form, status_code=400
        )

    agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    if agent.archived_at is not None:
        _flash(request, "This agent is archived — restore it before wiring an event source.")
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)

    name = name.strip()
    if not name:
        return await fail("Name is required.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    dup = await db.scalar(
        select(EventSource).where(
            EventSource.tenant_id == agent.tenant_id, EventSource.name == name
        )
    )
    if dup is not None:
        return await fail(f"An event source named {name!r} already exists in this tenant.")

    template, err = _form_json_object(payload_template, "Payload template")
    if err:
        return await fail(err)
    template = template or {"prompt": "{{body}}"}
    # Rendering happens per event, against a body nobody has seen yet, and a
    # template that cannot produce a job context fails at ingest — one 422 per
    # delivered event, in someone else's logs. Rendering it here against an
    # empty body is the one moment that mistake is cheap: substitutions come
    # out blank, so what is checked is the shape.
    try:
        JobContext.model_validate(render_template(template, {}))
    except ValidationError:
        return await fail(
            "The template does not produce a job context. It needs a non-empty "
            '"prompt" — the substitutions are blank when a field is missing from '
            "the event, so a prompt of only {{fields}} can render empty."
        )

    secret = "ss_evt_" + secrets.token_urlsafe(24)
    source = EventSource(
        tenant_id=agent.tenant_id,
        name=name,
        target_agent_id=agent.id,
        payload_template=template,
        dedup_key_path=dedup_key_path.strip() or None,
        secret_hash=hash_key(secret),
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return templates.TemplateResponse(
        request,
        "event_source_created.html",
        _ctx(
            request,
            p,
            tenant=await db.get(Tenant, agent.tenant_id),
            tenants=await _visible_tenants(db, p),
            section="agents",
            agent=agent,
            source=source,
            secret=secret,
            base_url=get_settings().public_base_url.rstrip("/"),
        ),
        status_code=201,
    )


@router.post("/agents/{agent_id}/event-sources/{source_id}/delete")
async def ui_delete_event_source(
    agent_id: uuid.UUID,
    source_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    _agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    source = await db.get(EventSource, source_id)
    if source is not None and source.target_agent_id == agent_id:
        await db.delete(source)
        await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/provider-creds")
async def ui_set_agent_provider_cred(
    request: Request,
    agent_id: uuid.UUID,
    provider: str = Form(""),
    api_key: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    error = await _set_provider_cred(db, KeyScope.AGENT, agent.id, provider, api_key)
    if error is not None:
        _flash(request, error)
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/provider-creds/delete")
async def ui_delete_agent_provider_cred(
    agent_id: uuid.UUID,
    provider: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent, redirect = await _key_admin_page(db, p, agent_id)
    if redirect is not None:
        return redirect
    await _delete_provider_cred(db, KeyScope.AGENT, agent.id, provider)
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


# --- Tenants ---
#
# Instance-level and superuser-only, like the models registry, so it hangs off
# /ui rather than a tenant path — and unlike everything else here, it is what
# you reach for when there is no tenant to be inside of yet.


async def _render_tenants(
    request: Request,
    db: AsyncSession,
    p: UserPrincipal,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
):
    tenants = await _visible_tenants(db, p)
    rows = list(await db.scalars(select(Tenant).order_by(Tenant.name)))
    teams = dict(
        (await db.execute(select(Team.tenant_id, func.count()).group_by(Team.tenant_id))).all()
    )
    agents = dict(
        (
            await db.execute(
                select(Agent.tenant_id, func.count())
                .where(Agent.archived_at.is_(None))
                .group_by(Agent.tenant_id)
            )
        ).all()
    )
    return templates.TemplateResponse(
        request,
        "tenants.html",
        _ctx(
            request,
            p,
            tenant=next(iter(tenants), None),
            tenants=tenants,
            section="tenants",
            rows=[
                {"tenant": t, "teams": teams.get(t.id, 0), "agents": agents.get(t.id, 0)}
                for t in rows
            ],
            error=error,
            form=form or {},
        ),
        status_code=status_code,
    )


@router.get("/tenants", response_class=HTMLResponse)
async def tenants_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui", status_code=303)
    return await _render_tenants(request, db, p)


@router.post("/tenants")
async def ui_create_tenant(
    request: Request,
    name: str = Form(""),
    system_prompt: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    if not p.user.is_superuser:
        return RedirectResponse("/ui", status_code=303)
    form = {"name": name, "system_prompt": system_prompt}

    async def fail(message: str):
        return await _render_tenants(request, db, p, error=message, form=form, status_code=400)

    name = name.strip()
    if not name:
        return await fail("Name is required.")
    if len(name) > 200:
        return await fail("Name must be 200 characters or fewer.")
    if await db.scalar(select(Tenant).where(Tenant.name == name)):
        return await fail(f"A tenant named {name!r} already exists.")

    tenant = Tenant(name=name, system_prompt=system_prompt.strip())
    db.add(tenant)
    await db.flush()
    # Every tenant is born with its org-wide team, as api.v1.tenants does:
    # owning it is what makes someone a tenant admin, so a tenant without one
    # can only ever be administered by an instance superuser.
    db.add(Team(tenant_id=tenant.id, name="org", is_org_team=True))
    await db.commit()
    return RedirectResponse(f"/ui/t/{tenant.id}", status_code=303)


# --- Invoke keys at tenant and team scope ---
#
# Agent-scoped keys live on the agent page. These two are wider — a tenant key
# can submit to every agent in the tenant and read every file in it, a team key
# to every agent in the team — so they sit where that scope is administered,
# next to the other things that carry it.


def _invoke_key_fields(name: str, rate_limit: str) -> tuple[str, int | None, str | None]:
    """The two fields an invoke key has, validated the same way wherever it is
    issued. Returns (name, rate limit, error)."""
    name = name.strip()
    if not name:
        return name, None, "Give the key a name — it is the only way to tell keys apart later."
    if len(name) > 200:
        return name, None, "Name must be 200 characters or fewer."
    if not rate_limit.strip():
        return name, None, None
    # Mirrors InvokeKeyCreate.rate_limit (ge=1); the upper bound is the UI's
    # own, since a limit past it is indistinguishable from no limit.
    limit, err = _form_int(rate_limit.strip(), 0, 1, 100000, "Rate limit")
    return name, (None if err else limit), err


async def _scoped_invoke_keys(
    db: AsyncSession, scope: KeyScope, scope_id: uuid.UUID
) -> list[ApiKey]:
    return list(
        await db.scalars(
            select(ApiKey)
            .where(
                ApiKey.kind == KeyKind.INVOKE,
                ApiKey.scope == scope,
                ApiKey.scope_id == scope_id,
            )
            .order_by(ApiKey.created_at.desc())
        )
    )


async def _mint_invoke_key(
    db: AsyncSession, scope: KeyScope, scope_id: uuid.UUID, name: str, rate_limit: int | None
) -> tuple[ApiKey, str]:
    plaintext, key_hash = generate_key(KeyKind.INVOKE)
    key = ApiKey(
        kind=KeyKind.INVOKE,
        scope=scope,
        scope_id=scope_id,
        key_hash=key_hash,
        name=name,
        rate_limit=rate_limit,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key, plaintext


async def _revoke_invoke_key(
    db: AsyncSession, key_id: uuid.UUID, scope: KeyScope, scope_id: uuid.UUID
) -> None:
    key = await db.get(ApiKey, key_id)
    if (
        key is not None
        and key.kind == KeyKind.INVOKE
        and key.scope == scope
        and key.scope_id == scope_id
        and key.revoked_at is None
    ):
        key.revoked_at = datetime.now(UTC)
        await db.commit()


@router.post("/t/{tenant_id}/invoke-keys")
async def ui_create_tenant_invoke_key(
    request: Request,
    tenant_id: uuid.UUID,
    name: str = Form(""),
    rate_limit: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect
    name, limit, error = _invoke_key_fields(name, rate_limit)
    if error is not None:
        return await _render_settings(request, tenant_id, db, p, error=error, status_code=400)
    key, plaintext = await _mint_invoke_key(db, KeyScope.TENANT, tenant.id, name, limit)
    # Rendered into this response rather than flashed: the session cookie is
    # signed but not encrypted, so a flash would park a live data-plane
    # credential in the browser's cookie jar.
    return await _render_settings(
        request, tenant_id, db, p, created_key=key, plaintext=plaintext, status_code=201
    )


@router.post("/t/{tenant_id}/invoke-keys/{key_id}/revoke")
async def ui_revoke_tenant_invoke_key(
    tenant_id: uuid.UUID,
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    tenant, redirect = await _tenant_admin_or_redirect(db, p, tenant_id)
    if redirect is not None:
        return redirect
    await _revoke_invoke_key(db, key_id, KeyScope.TENANT, tenant.id)
    return RedirectResponse(f"/ui/t/{tenant_id}/settings", status_code=303)


@router.post("/teams/{team_id}/invoke-keys")
async def ui_create_team_invoke_key(
    request: Request,
    team_id: uuid.UUID,
    name: str = Form(""),
    rate_limit: str = Form(""),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect
    name, limit, error = _invoke_key_fields(name, rate_limit)
    if error is not None:
        return await _render_team(request, team_id, db, p, error=error, status_code=400)
    key, plaintext = await _mint_invoke_key(db, KeyScope.TEAM, team.id, name, limit)
    return await _render_team(
        request, team_id, db, p, created_key=key, plaintext=plaintext, status_code=201
    )


@router.post("/teams/{team_id}/invoke-keys/{key_id}/revoke")
async def ui_revoke_team_invoke_key(
    team_id: uuid.UUID,
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    team, redirect = await _team_owner_or_redirect(db, p, team_id)
    if redirect is not None:
        return redirect
    await _revoke_invoke_key(db, key_id, KeyScope.TEAM, team.id)
    return RedirectResponse(f"/ui/teams/{team_id}", status_code=303)


# --- Actions (owner/editor gated, mirroring the API) ---


@router.post("/agents/{agent_id}/promote/{version_no}")
async def ui_promote(
    agent_id: uuid.UUID,
    version_no: int,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent and await _team_role(db, p, agent.team_id) == Role.OWNER:
        version = await db.scalar(
            select(AgentVersion).where(
                AgentVersion.agent_id == agent_id, AgentVersion.version_no == version_no
            )
        )
        if version is not None:
            agent.current_version_id = version.id
            await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/aliases")
async def ui_set_alias(
    agent_id: uuid.UUID,
    alias: str = Form(),
    version_no: int = Form(),
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    from sleeper_service.api.v1.schemas import ALIAS_PATTERN

    agent = await db.get(Agent, agent_id)
    alias = alias.strip().lower()
    if (
        agent
        and re.fullmatch(ALIAS_PATTERN, alias)
        and await _team_role(db, p, agent.team_id) == Role.OWNER
    ):
        version = await db.scalar(
            select(AgentVersion).where(
                AgentVersion.agent_id == agent_id, AgentVersion.version_no == version_no
            )
        )
        if version is not None:
            row = await db.get(VersionAlias, (agent_id, alias))
            if row is None:
                db.add(VersionAlias(agent_id=agent_id, alias=alias, agent_version_id=version.id))
            else:
                row.agent_version_id = version.id
            await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/aliases/{alias}/delete")
async def ui_delete_alias(
    agent_id: uuid.UUID,
    alias: str,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent and await _team_role(db, p, agent.team_id) == Role.OWNER:
        row = await db.get(VersionAlias, (agent_id, alias))
        if row is not None:
            await db.delete(row)
            await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/memory/{version_no}/{action}")
async def ui_memory_action(
    agent_id: uuid.UUID,
    version_no: int,
    action: str,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if (
        agent
        and action in ("approve", "reject")
        and await _team_role(db, p, agent.team_id) == Role.OWNER
    ):
        version = await db.scalar(
            select(MemoryVersion).where(
                MemoryVersion.agent_id == agent_id, MemoryVersion.version_no == version_no
            )
        )
        if version is not None and version.status == "pending":
            version.status = "active" if action == "approve" else "rejected"
            await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/agents/{agent_id}/memory/rollback")
async def ui_memory_rollback(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    agent = await db.get(Agent, agent_id)
    if agent and await _team_role(db, p, agent.team_id) == Role.OWNER:
        latest = await db.scalar(
            select(MemoryVersion)
            .where(MemoryVersion.agent_id == agent_id, MemoryVersion.status == "active")
            .order_by(MemoryVersion.version_no.desc())
            .limit(1)
        )
        if latest is not None:
            latest.status = "rejected"
            await db.commit()
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/jobs/{job_id}/retry")
async def ui_retry_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    from sleeper_service.queue import get_pool

    job = await db.get(Job, job_id)
    if job is not None and job.status in ("dead_letter", "failed", "timeout"):
        agent = await db.get(Agent, job.agent_id)
        if agent.archived_at is None and await _team_role(db, p, agent.team_id) in (
            Role.OWNER,
            Role.EDITOR,
        ):
            job.status = "queued"
            job.output = None
            job.error = None
            job.started_at = None
            job.finished_at = None
            db.add(JobEvent(job_id=job.id, type="retried", data={"by": "ui"}))
            await db.commit()
            pool = await get_pool()
            await pool.enqueue_job("run_job", str(job.id))
    return RedirectResponse(f"/ui/jobs/{job_id}", status_code=303)
