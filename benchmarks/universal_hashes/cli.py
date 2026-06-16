import typer

from benchmarks.universal_hashes.ghash.cli import app as ghash_app
from benchmarks.universal_hashes.polyval.cli import app as polyval_app

app = typer.Typer(help="Universal hash benchmarks.")
app.add_typer(ghash_app, name="ghash")
app.add_typer(polyval_app, name="polyval")
