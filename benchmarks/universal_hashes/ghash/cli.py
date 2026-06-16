import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="GHASH benchmarks.")


def _bench(backend: str) -> None:
    run_bench(f"benchmarks/universal_hashes/ghash/{backend}.mojo")


@app.command()
def cpu() -> None:
    """Benchmark GHASH using the portable CPU backend."""
    _bench("cpu")
