import subprocess

import typer

app = typer.Typer(help="Hex encoding benchmarks.")


def _bench(backend: str) -> None:
    subprocess.run(
        ["mojo", "run", "-O3", "-I", ".", f"benchmarks/containers/encoding/hex/{backend}.mojo"],
        check=True,
    )


@app.command()
def cpu() -> None:
    """Benchmark hex encode/decode using the CPU backend."""
    _bench("cpu")


@app.command()
def gpu() -> None:
    """Benchmark hex encode/decode using the CUDA GPU backend."""
    _bench("gpu")
