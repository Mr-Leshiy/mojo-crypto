import typer

from benchmarks.universal_hashes.polyval.cli import app as polyval_app

app = typer.Typer(help="Universal hash benchmarks.")
app.add_typer(polyval_app, name="polyval")
