import typer

from benchmarks.block_ciphers.cli import app as block_ciphers_app

app = typer.Typer(help="mojo-crypto benchmarks.")
app.add_typer(block_ciphers_app, name="block_ciphers")

if __name__ == "__main__":
    app()
