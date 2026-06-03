import typer

from benchmarks.containers.encoding.hex.cli import app as hex_app

app = typer.Typer(help="Encoding benchmarks.")
app.add_typer(hex_app, name="hex")
