import subprocess


def run_bench(path: str, defines: dict[str, str] | None = None) -> None:
    flags = [f"-D{name}={value}" for name, value in (defines or {}).items()]
    subprocess.run(["mojo", "run", "-O3", *flags, "-I", ".", path], check=True)
