import typer

from benchmarks.block_ciphers.aes.cli import app as aes_app

app = typer.Typer(help="mojo-crypto benchmarks.")
app.add_typer(aes_app, name="aes")

if __name__ == "__main__":
    app()
