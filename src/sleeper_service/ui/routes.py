"""Admin UI: server-rendered, session-authenticated, per-tenant.

Deviation from BUILD_PLAN (2026-08-02): plain session-cookie auth against the
existing users table instead of fastapi-users — we already own the user rows
and pwdlib hashing, so fastapi-users would add machinery without adding
capability. OIDC remains planned as an additive option.

RBAC mirrors the API exactly: any team role makes a thing visible; owner
promotes versions and approves memory; editor retries jobs.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import escape
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.auth.passwords import verify_password
from sleeper_service.auth.principal import UserPrincipal
from sleeper_service.constants import Role
from sleeper_service.db.models import (
    Agent,
    AgentVersion,
    EvalCase,
    EvalRun,
    Job,
    JobEvent,
    MemoryVersion,
    Model,
    Team,
    TeamMember,
    Tenant,
    User,
)
from sleeper_service.db.session import get_db
from sleeper_service.runtime import spending
from sleeper_service.runtime.memory import latest_memory

router = APIRouter(prefix="/ui", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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
    return UserPrincipal(user=user, roles={m.team_id: Role(m.role) for m in memberships})


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


def _ctx(request: Request, p: UserPrincipal, **extra) -> dict:
    return {"request": request, "user": p.user, **extra}


async def _team_role(db: AsyncSession, p: UserPrincipal, team_id: uuid.UUID) -> Role | None:
    if p.is_superuser:
        return Role.OWNER
    return p.roles.get(team_id)


# --- Auth ---


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(User).where(User.email == email))
    if user is None or not user.password_hash or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid email or password"}, status_code=401
        )
    request.session["user_id"] = str(user.id)
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
    tenant_agents = select(Agent.id).where(Agent.tenant_id == tenant.id)
    now = datetime.now(UTC)

    total_agents = await db.scalar(
        select(func.count()).select_from(Agent).where(Agent.tenant_id == tenant.id)
    )
    live_agents = await db.scalar(
        select(func.count())
        .select_from(Agent)
        .where(Agent.tenant_id == tenant.id, Agent.current_version_id.is_not(None))
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

    # charts: last 14 days
    since = now - timedelta(days=13)
    day = func.date_trunc("day", Job.created_at)
    rows = (
        await db.execute(
            select(day.label("day"), Job.status, func.count())
            .where(Job.agent_id.in_(tenant_agents), Job.created_at >= since)
            .group_by(day, Job.status)
        )
    ).all()
    token_rows = (
        await db.execute(
            select(
                day.label("day"),
                func.sum(Job.tokens_in),
                func.sum(Job.tokens_out),
            )
            .where(Job.agent_id.in_(tenant_agents), Job.created_at >= since)
            .group_by(day)
        )
    ).all()

    days = [(since + timedelta(days=i)).date() for i in range(14)]
    labels = [d.strftime("%m-%d") for d in days]
    statuses = sorted({status for _, status, _ in rows})
    by_day_status = {(d.date(), s): c for d, s, c in rows}
    jobs_chart = {
        "labels": labels,
        "statuses": [
            {"name": s, "counts": [by_day_status.get((d, s), 0) for d in days]} for s in statuses
        ],
    }
    by_day_tokens = {d.date(): (ti or 0, to or 0) for d, ti, to in token_rows}
    tokens_chart = {
        "labels": labels,
        "tokens_in": [by_day_tokens.get(d, (0, 0))[0] for d in days],
        "tokens_out": [by_day_tokens.get(d, (0, 0))[1] for d in days],
    }

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
            jobs_chart=json.dumps(jobs_chart),
            tokens_chart=json.dumps(tokens_chart),
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
    for team in teams:
        role = await _team_role(db, p, team.id)
        if role is None:
            continue
        agents = list(
            await db.scalars(select(Agent).where(Agent.team_id == team.id).order_by(Agent.name))
        )
        agent_views = []
        for a in agents:
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
                "name": team.name,
                "is_org_team": team.is_org_team,
                "role": role.value if role else None,
                "agents": agent_views,
            }
        )

    return templates.TemplateResponse(
        request,
        "agents.html",
        _ctx(request, p, tenant=tenant, tenants=tenants, section="agents", teams=team_views),
    )


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
    versions = [
        {
            "id": v.id,
            "version_no": v.version_no,
            "prompt": v.prompt,
            "model_string": model_string or "?",
            "max_iterations": v.max_iterations,
            "timeout_s": v.timeout_s,
            "created_at": v.created_at,
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
    eval_case_count = await db.scalar(
        select(func.count()).select_from(EvalCase).where(EvalCase.agent_id == agent.id)
    )
    recent_jobs = list(
        await db.scalars(
            select(Job).where(Job.agent_id == agent.id).order_by(Job.created_at.desc()).limit(10)
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
            current_memory=current_memory,
            pending_memory=pending_memory,
            eval_runs=eval_runs,
            eval_case_count=eval_case_count,
            recent_jobs=recent_jobs,
            can_promote=role == Role.OWNER,
        ),
    )


# --- Jobs ---


async def _render_tree(db: AsyncSession, job: Job) -> str:
    children = list(
        await db.scalars(select(Job).where(Job.parent_job_id == job.id).order_by(Job.created_at))
    )
    if not children:
        return ""
    parts = ["<ul>"]
    for child in children:
        agent = await db.get(Agent, child.agent_id)
        parts.append(
            f'<li><span class="badge {escape(child.status)}">{escape(child.status)}</span> '
            f"<strong>{escape(agent.name if agent else '?')}</strong> "
            f'<a class="mono" href="/ui/jobs/{child.id}">{str(child.id)[:8]}</a>'
            f"{await _render_tree(db, child)}</li>"
        )
    parts.append("</ul>")
    return "".join(parts)


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
    tree_html = await _render_tree(db, job)

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
        if await _team_role(db, p, agent.team_id) in (Role.OWNER, Role.EDITOR):
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
