import subprocess

import typer

app = typer.Typer(help="AES benchmarks.")


def _bench(backend: str) -> None:
    subprocess.run(
        ["mojo", "run", "-O3", "-I", ".", f"benchmarks/aes/{backend}.mojo"],
        check=True,
    )


@app.command()
def cpu() -> None:
    """Benchmark AES-128/192/256 using the portable CPU backend."""
    _bench("cpu")


@app.command()
def armv8() -> None:
    """Benchmark AES-128/192/256 using the ARMv8 Crypto Extension backend."""
    _bench("armv8")


@app.command()
def x86() -> None:
    """Benchmark AES-128/192/256 using the x86 AES-NI backend."""
    _bench("x86")


@app.command()
def gpu() -> None:
    """Benchmark AES-128/192/256 using the CUDA GPU backend."""
    _bench("gpu")
