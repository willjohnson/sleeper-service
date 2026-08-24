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
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import escape
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.agents import GOVERNED_OPTION_KEYS
from sleeper_service.api.v1.schemas import JobContext
from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.passwords import verify_password
from sleeper_service.auth.principal import UserPrincipal
from sleeper_service.auth.rbac import is_tenant_admin, visible_team_ids
from sleeper_service.config import get_settings
from sleeper_service.constants import KeyKind, KeyScope, Role
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    ApiKey,
    EvalCase,
    EvalRun,
    Job,
    JobEvent,
    MemoryVersion,
    Model,
    OidcConfig,
    Team,
    TeamMember,
    Tenant,
    User,
    VersionAlias,
)
from sleeper_service.db.session import get_db
from sleeper_service.runtime import spending
from sleeper_service.runtime.evals import PATH_OPS, validate_checks
from sleeper_service.runtime.memory import latest_memory

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
    return UserPrincipal(user=user, roles=roles)


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

    Grants are carried rather than collected: the form has no registry to pick
    from yet (docs/TODO § Admin UI parity), so the caller passes the outgoing
    version's lists through and a UI-published version stops silently dropping
    the tools and stores its predecessor had."""
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
        return await fail(f"Unknown model {model!r} — register it in the models registry first.")

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
            can_promote=role == Role.OWNER,
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


# --- Invoke keys ---
#
# Agent-scoped data-plane keys only: those are what make an agent built in the
# UI actually callable. Tenant- and team-scoped keys stay on the API until
# there is a settings section with somewhere to put them.


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
            carried_grants=(
                current.tool_grants + [g.get("store", "?") for g in current.data_store_grants]
            )
            if current
            else [],
            next_version_no=(current.version_no + 1) if current else 1,
            error=error,
            form=form or {},
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
    db: AsyncSession = Depends(get_db),
    p: UserPrincipal = Depends(ui_user),
):
    form = {
        "model": model,
        "prompt": prompt,
        "max_iterations": max_iterations,
        "timeout_s": timeout_s,
        "output_schema": output_schema,
        "input_schema": input_schema,
        "params": params,
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
        return await fail(f"Unknown model {model!r} — register it in the models registry first.")

    current = (
        await db.get(AgentVersion, agent.current_version_id) if agent.current_version_id else None
    )
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
        tool_grants=current.tool_grants if current else None,
        data_store_grants=current.data_store_grants if current else None,
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
        ),
    )


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
