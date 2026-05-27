import typer

from benchmarks.block_ciphers.aes.cli import app as aes_app

app = typer.Typer(help="Block Ciphers benchmarks.")
app.add_typer(aes_app, name="aes")

