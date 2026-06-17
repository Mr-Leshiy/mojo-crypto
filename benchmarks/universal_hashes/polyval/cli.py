import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="POLYVAL benchmarks.")


def _bench(backend: str) -> None:
    run_bench(f"benchmarks/universal_hashes/polyval/{backend}.mojo")


@app.command()
def cpu() -> None:
    """Benchmark POLYVAL using the portable CPU backend."""
    _bench("cpu")


@app.command()
def aarch64() -> None:
    """Benchmark POLYVAL using the ARMv8 NEON + PMULL backend."""
    _bench("aarch64")
