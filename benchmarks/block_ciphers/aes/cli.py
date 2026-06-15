import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="AES benchmarks.")


def _bench(backend: str) -> None:
    run_bench(f"benchmarks/block_ciphers/aes/{backend}.mojo")


@app.command()
def cpu() -> None:
    """Benchmark AES-128/192/256 using the portable CPU backend."""
    _bench("cpu")


@app.command()
def aarch64() -> None:
    """Benchmark AES-128/192/256 using the Aarch64 Crypto Extension backend."""
    _bench("aarch64")


@app.command()
def x86() -> None:
    """Benchmark AES-128/192/256 using the x86 AES-NI backend."""
    _bench("x86")


@app.command()
def gpu() -> None:
    """Benchmark AES-128/192/256 using the CUDA GPU backend."""
    _bench("gpu")
