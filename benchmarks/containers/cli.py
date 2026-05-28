import typer

from benchmarks.containers.encoding.cli import app as encoding_app

app = typer.Typer(help="Containers benchmarks.")
app.add_typer(encoding_app, name="encoding")
