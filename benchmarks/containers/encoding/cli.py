import subprocess

import typer

app = typer.Typer(help="Encoding benchmarks.")


@app.command()
def hex() -> None:
    """Benchmark hex encode/decode at 1 KB, 4 KB, and 16 KB."""
    subprocess.run(
        ["mojo", "run", "-O3", "-I", ".", "benchmarks/containers/encoding/hex.mojo"],
        check=True,
    )
