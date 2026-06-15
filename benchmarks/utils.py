import subprocess


def run_bench(path: str) -> None:
    subprocess.run(["mojo", "run", "-O3", "-I", ".", path], check=True)
