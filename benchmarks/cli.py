import typer

from benchmarks.block_ciphers.cli import app as block_ciphers_app
from benchmarks.universal_hashes.cli import app as universal_hashes_app

app = typer.Typer(help="mojo-crypto benchmarks.")
app.add_typer(block_ciphers_app, name="block_ciphers")
app.add_typer(universal_hashes_app, name="universal_hashes")

if __name__ == "__main__":
    app()
