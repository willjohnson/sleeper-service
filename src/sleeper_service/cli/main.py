import asyncio
import json
import uuid as uuid_mod

import typer
from sqlalchemy import func, select

from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.passwords import hash_password
from sleeper_service.config import get_settings
from sleeper_service.constants import KeyKind, Role
from sleeper_service.db.models import ApiKey, Team, TeamMember, Tenant, User
from sleeper_service.db.session import get_sessionmaker

app = typer.Typer(help="Sleeper Service administration CLI.")


@app.callback()
def cli() -> None:
    """Keep subcommand names (`sleeper init`) even while there is one command."""


@app.command()
def init(
    tenant_name: str = typer.Option("default", help="Name of the first tenant."),
    email: str = typer.Option(..., prompt=True, help="Email of the first (super)user."),
    password: str = typer.Option(
        ...,
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Password of the first user.",
    ),
) -> None:
    """Bootstrap the first tenant, org team, owner user, and API key."""
    asyncio.run(_init(tenant_name, email, password))


async def _init(tenant_name: str, email: str, password: str) -> None:
    async with get_sessionmaker()() as db:
        if await db.scalar(select(Tenant).limit(1)) or await db.scalar(select(User).limit(1)):
            typer.secho("Already initialized — tenants or users exist.", fg="red")
            raise typer.Exit(code=1)

        tenant = Tenant(name=tenant_name)
        db.add(tenant)
        await db.flush()

        team = Team(tenant_id=tenant.id, name="org", is_org_team=True)
        user = User(email=email, password_hash=hash_password(password), is_superuser=True)
        db.add_all([team, user])
        await db.flush()

        db.add(TeamMember(user_id=user.id, team_id=team.id, role=Role.OWNER))
        plaintext, key_hash = generate_key(KeyKind.USER)
        db.add(ApiKey(kind=KeyKind.USER, user_id=user.id, key_hash=key_hash, name="bootstrap"))
        await db.commit()

    typer.secho("Sleeper Service initialized.", fg="green", bold=True)
    typer.echo(f"  Tenant:   {tenant.name} ({tenant.id})")
    typer.echo(f"  Org team: {team.name} ({team.id})")
    typer.echo(f"  User:     {user.email} ({user.id}) [superuser]")
    typer.echo("\nYour API key (shown once — store it now):\n")
    typer.secho(f"  {plaintext}\n", bold=True)


SEED_MODELS = [
    ("anthropic", "claude-sonnet-5", "anthropic:claude-sonnet-5"),
    ("anthropic", "claude-opus-5", "anthropic:claude-opus-5"),
    ("anthropic", "claude-haiku-4-5", "anthropic:claude-haiku-4-5-20251001"),
    ("test", "default", "test:default"),
    ("test", "flaky", "test:flaky"),  # always-503 model for DLQ/alerting demos
]


@app.command()
def seed_models() -> None:
    """Register a starter set of models (idempotent). Add more via the API."""
    asyncio.run(_seed_models())


async def _seed_models() -> None:
    from sleeper_service.db.models import Model

    async with get_sessionmaker()() as db:
        added = 0
        for provider, name, model_string in SEED_MODELS:
            exists = await db.scalar(
                select(Model).where(Model.provider == provider, Model.name == name)
            )
            if exists is None:
                db.add(Model(provider=provider, name=name, model_string=model_string))
                added += 1
        await db.commit()
    typer.secho(f"Models seeded ({added} added, {len(SEED_MODELS) - added} existing).", fg="green")


# --- Demo (BUILD_PLAN § Event sources: anchor use case) ---

DEMO_NS = uuid_mod.uuid5(uuid_mod.NAMESPACE_URL, "sleeper-service-demo")

RISK_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
        "factors": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
    "required": ["risk_level", "factors", "summary"],
}

RISK_PROMPT = """You are a business risk analyst for a retail company.

Before assessing any event, read the file 'risk_playbook.md' from the
'reference' data store (use the read_file tool with store_name='reference')
— it defines the company's locations and risk thresholds. Ground your
assessment in that playbook: cite which thresholds or locations apply.

If (and only if) you conclude risk_level is "high": use list_agents to find
the notification agent and call_agent to have it alert the operations team
with a one-line description of the risk. Do this before returning your
assessment."""

NOTIFIER_SCHEMA = {
    "type": "object",
    "properties": {
        "channel": {"type": "string", "enum": ["ops"]},
        "message": {"type": "string"},
    },
    "required": ["channel", "message"],
}

NOTIFIER_PROMPT = """You are the operations notifier. Turn the request in the
payload into one short, urgent, actionable alert message for the operations
team. channel is always "ops"."""

PLAYBOOK = """# Risk playbook

## Company footprint
- Distribution centers: St. Louis MO, Denver CO
- HQ: Chicago IL
- Overnight logistics depend on the St. Louis hub.

## Thresholds
- Any single-day stock move beyond ±5% on watched tickers (AAPL, MSFT, our
  own listing) => at least MEDIUM market risk.
- Severe weather warnings within 50 miles of a distribution center => HIGH
  operational risk during the warning window.
- Staffing below 80% on any shift at a distribution center => escalate one
  level.
"""


def demo_source_identity(name: str) -> tuple[str, str]:
    """Deterministic (source_id, secret) derived from SECRET_KEY, so the demo
    poller — an external script — can compute them from the shared .env
    without holding any platform API key."""
    import hashlib
    import hmac as hmac_mod

    secret_key = get_settings().secret_key.encode()
    digest = hmac_mod.new(secret_key, f"demo-source:{name}".encode(), hashlib.sha256)
    source_id = str(uuid_mod.uuid5(DEMO_NS, name))
    return source_id, "ss_evt_demo_" + digest.hexdigest()[:32]


@app.command()
def demo_setup() -> None:
    """Create the demo tenant: risk-analyzer on an event feed, reference data
    store, budget, flaky agent (dead-letter demo), and alert channel."""
    asyncio.run(_demo_setup())


async def _demo_setup() -> None:
    import os
    from decimal import Decimal

    from sleeper_service.auth.keys import hash_key
    from sleeper_service.config import get_settings as gs
    from sleeper_service.crypto import encrypt
    from sleeper_service.db.models import (
        Agent,
        AgentVersion,
        DataStore,
        EventSource,
        Model,
        NotifChannel,
    )

    settings = gs()
    await _seed_models()

    async with get_sessionmaker()() as db:
        tenant = await db.scalar(select(Tenant).where(Tenant.name == "demo"))
        if tenant is None:
            tenant = Tenant(name="demo", system_prompt="Be concise and factual.")
            db.add(tenant)
            await db.flush()
            db.add(Team(tenant_id=tenant.id, name="org", is_org_team=True))
            await db.flush()
        team = await db.scalar(
            select(Team).where(Team.tenant_id == tenant.id, Team.is_org_team.is_(True))
        )

        # Model: real (OpenRouter) when a key is configured, else the test model
        use_real = bool(os.environ.get("OPENROUTER_API_KEY"))
        if use_real:
            model = await db.scalar(select(Model).where(Model.provider == "openrouter"))
            if model is None:
                model = Model(
                    provider="openrouter",
                    name="gemini-2.5-flash-lite",
                    model_string="openrouter:google/gemini-2.5-flash-lite",
                )
                db.add(model)
                await db.flush()
        else:
            model = await db.scalar(
                select(Model).where(Model.provider == "test", Model.name == "default")
            )
        flaky_model = await db.scalar(
            select(Model).where(Model.provider == "test", Model.name == "flaky")
        )

        # Reference data store (MinIO bucket, read-only grant)
        store = await db.scalar(
            select(DataStore).where(DataStore.tenant_id == tenant.id, DataStore.name == "reference")
        )
        if store is None:
            store = DataStore(
                tenant_id=tenant.id,
                name="reference",
                type="s3",
                config={"bucket": "demo-reference", "endpoint_url": settings.minio_endpoint},
                credentials_enc=encrypt(
                    json.dumps(
                        {
                            "access_key": settings.minio_access_key,
                            "secret_key": settings.minio_secret_key,
                        }
                    )
                ),
            )
            db.add(store)

        async def ensure_agent(
            name: str,
            description: str,
            model_row: Model,
            prompt: str,
            schema: dict | None,
            grants: list,
            limit: Decimal | None,
            options: dict | None = None,
        ) -> Agent:
            """Upsert: options/description always refresh; a changed prompt or
            model becomes a new promoted version (versions stay immutable)."""
            agent = await db.scalar(
                select(Agent).where(Agent.tenant_id == tenant.id, Agent.name == name)
            )
            if agent is None:
                agent = Agent(tenant_id=tenant.id, team_id=team.id, name=name)
                db.add(agent)
            agent.description = description
            agent.spending_limit = limit
            agent.options = options or {}
            await db.flush()

            current = (
                await db.get(AgentVersion, agent.current_version_id)
                if agent.current_version_id
                else None
            )
            if (
                current is None
                or current.prompt != prompt
                or current.model_id != model_row.id
                or current.max_iterations != 12
            ):
                next_no = (
                    await db.scalar(
                        select(func.coalesce(func.max(AgentVersion.version_no), 0)).where(
                            AgentVersion.agent_id == agent.id
                        )
                    )
                    + 1
                )
                version = AgentVersion(
                    agent_id=agent.id,
                    version_no=next_no,
                    prompt=prompt,
                    model_id=model_row.id,
                    # enough for: playbook read + rolodex + delegation + retries
                    max_iterations=12,
                    timeout_s=120,
                    output_schema=schema,
                    data_store_grants=grants,
                )
                db.add(version)
                await db.flush()
                agent.current_version_id = version.id
            return agent

        risk = await ensure_agent(
            "risk-analyzer",
            "Assesses business risk for events from the market/weather feed",
            model,
            RISK_PROMPT if use_real else "Assess business risk for the event.",
            RISK_SCHEMA,
            [{"store": "reference", "prefix": "", "mode": "ro"}] if use_real else [],
            Decimal("1.00"),
            options={"delegation": "team", "memory": True, "learning": True},
        )
        await ensure_agent(
            "notifier",
            "Sends an urgent alert to the operations team about a business risk",
            model,
            NOTIFIER_PROMPT,
            NOTIFIER_SCHEMA,
            [],
            Decimal("0.50"),
        )
        flaky = await ensure_agent(
            "flaky-agent",
            "Always fails transiently — demonstrates retries, DLQ, and alerting",
            flaky_model,
            "This never runs.",
            None,
            [],
            None,
        )

        # Event sources with deterministic ids/secrets (poller derives them)
        for source_name, agent in (("market", risk), ("flaky", flaky)):
            source_id, secret = demo_source_identity(source_name)
            source = await db.get(EventSource, uuid_mod.UUID(source_id))
            if source is None:
                db.add(
                    EventSource(
                        id=uuid_mod.UUID(source_id),
                        tenant_id=tenant.id,
                        name=f"demo-{source_name}",
                        target_agent_id=agent.id,
                        payload_template={
                            "prompt": "Assess business risk for this event: {{body}}"
                        },
                        dedup_key_path="event.id",
                        secret_hash=hash_key(secret),
                    )
                )

        # Alert channel → demo-sink echo container (dead_letter + budget)
        channel = await db.scalar(select(NotifChannel).where(NotifChannel.team_id == team.id))
        if channel is None:
            db.add(
                NotifChannel(
                    team_id=team.id,
                    apprise_url_enc=encrypt("json://demo-sink:8080/alerts"),
                    events=["dead_letter", "budget"],
                )
            )
        await db.commit()

    # Seed the reference bucket
    import fsspec

    fs = fsspec.filesystem(
        "s3",
        key=settings.minio_access_key,
        secret=settings.minio_secret_key,
        endpoint_url=settings.minio_endpoint,
    )
    if not fs.exists("demo-reference"):
        fs.mkdir("demo-reference")
    fs.pipe_file("demo-reference/risk_playbook.md", PLAYBOOK.encode())

    typer.secho("Demo ready.", fg="green", bold=True)
    typer.echo(f"  Model: {'openrouter (real)' if use_real else 'test provider (no key set)'}")
    typer.echo("  Agents: risk-analyzer (delegation+memory+learning), notifier, flaky-agent")
    typer.echo("  Reference store: s3://demo-reference/risk_playbook.md (read-only grant)")
    typer.echo("  Alerts: json://demo-sink:8080/alerts (dead_letter, budget)")
    typer.echo("\nStart the feed: docker compose --profile demo up -d")


if __name__ == "__main__":
    app()
