import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="SHA-2 benchmarks.")


def _bench(backend: str) -> None:
    run_bench(f"benchmarks/hashes/sha2/{backend}.mojo")


@app.command()
def naive() -> None:
    """Benchmark SHA-224/256/384/512 and SHA-512/t using the portable naive backend."""
    _bench("naive")


@app.command()
def aarch64() -> None:
    """Benchmark SHA-224/256/384/512 and SHA-512/t using the Aarch64 Crypto Extension backend."""
    _bench("aarch64")


@app.command()
def x86() -> None:
    """Benchmark SHA-224/256/384/512 and SHA-512/t using the x86 SHA-NI/SHA512 backend."""
    _bench("x86")
