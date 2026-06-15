import subprocess

import typer

app = typer.Typer(help="POLYVAL benchmarks.")


def _bench(backend: str) -> None:
    subprocess.run(
        ["mojo", "run", "-O3", "-I", ".", f"benchmarks/universal_hashes/polyval/{backend}.mojo"],
        check=True,
    )


@app.command()
def cpu() -> None:
    """Benchmark POLYVAL using the portable CPU backend."""
    _bench("cpu")
