import typer

app = typer.Typer(help="Solidity Sentinel CLI")


@app.callback()
def main() -> None:
    """Solidity Sentinel command group."""

