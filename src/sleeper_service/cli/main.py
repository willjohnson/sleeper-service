import typer

app = typer.Typer(help="Sleeper Service administration CLI.")


@app.command()
def init() -> None:
    """Bootstrap the first tenant, org team, owner user, and API key."""
    raise typer.Exit(code=1)  # implemented in Phase 0 bootstrap step


if __name__ == "__main__":
    app()
