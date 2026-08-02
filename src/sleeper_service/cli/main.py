import asyncio

import typer
from sqlalchemy import select

from sleeper_service.auth.keys import generate_key
from sleeper_service.auth.passwords import hash_password
from sleeper_service.constants import KeyKind, Role
from sleeper_service.db.models import ApiKey, Team, TeamMember, Tenant, User
from sleeper_service.db.session import get_sessionmaker

app = typer.Typer(help="Sleeper Service administration CLI.")


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


if __name__ == "__main__":
    app()
