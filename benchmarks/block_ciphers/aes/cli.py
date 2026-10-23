from enum import Enum

import typer

from benchmarks.utils import run_bench

app = typer.Typer(help="AES benchmarks.")


class Mode(str, Enum):
    """Block cipher mode of operation the benchmark runs AES under."""

    ecb = "ecb"
    cbc = "cbc"
    ctr = "ctr"


ModeOption = typer.Option(Mode.ecb, "--mode", help="Mode of operation.")


def _bench(backend: str, mode: Mode) -> None:
    run_bench(
        f"benchmarks/block_ciphers/aes/{backend}.mojo",
        defines={"MODE": mode.value},
    )


@app.command()
def naive(mode: Mode = ModeOption) -> None:
    """Benchmark AES-128/192/256 using the portable naive backend."""
    _bench("naive", mode)


@app.command()
def aarch64(mode: Mode = ModeOption) -> None:
    """Benchmark AES-128/192/256 using the Aarch64 Crypto Extension backend."""
    _bench("aarch64", mode)


@app.command()
def x86(mode: Mode = ModeOption) -> None:
    """Benchmark AES-128/192/256 using the x86 AES-NI backend."""
    _bench("x86", mode)


@app.command()
def gpu(mode: Mode = ModeOption) -> None:
    """Benchmark AES-128/192/256 using the CUDA GPU backend."""
    _bench("gpu", mode)
