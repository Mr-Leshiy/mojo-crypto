import typer

from benchmarks.hashes.sha2.cli import app as sha2_app

app = typer.Typer(help="Hash benchmarks.")
app.add_typer(sha2_app, name="sha2")
