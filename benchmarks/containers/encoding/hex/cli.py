import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="Hex encoding benchmarks.")


def _bench(backend: str) -> None:
    run_bench(f"benchmarks/containers/encoding/hex/{backend}.mojo")


@app.command()
def cpu() -> None:
    """Benchmark hex encode/decode using the CPU backend."""
    _bench("cpu")


@app.command()
def gpu() -> None:
    """Benchmark hex encode/decode using the CUDA GPU backend."""
    _bench("gpu")
