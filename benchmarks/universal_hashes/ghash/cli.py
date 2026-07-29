import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="GHASH benchmarks.")


def _bench(backend: str) -> None:
    run_bench(f"benchmarks/universal_hashes/ghash/{backend}.mojo")


@app.command()
def naive() -> None:
    """Benchmark GHASH using the portable naive backend."""
    _bench("naive")

@app.command()
def aarch64() -> None:
    """Benchmark GHASH using the portable Aarch64 backend."""
    _bench("aarch64")


@app.command()
def x86() -> None:
    """Benchmark GHASH using the x86 PCLMULQDQ backend."""
    _bench("x86")
