#!/usr/bin/env python3
"""Compile-only checks for the Mojo benchmarks.

Verifies each backend builds without running it (running requires a GPU /
specific host CPU), so the per-backend target flags below are cross-compilation
targets rather than the host's. Output goes to a temporary directory that is
discarded afterwards. Stops at the first backend that fails to build.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

AARCH64 = ["--target-triple=aarch64-unknown-linux-gnu", "--target-features=+neon,+aes"]
X86_AES = ["--target-triple=x86_64-unknown-linux-gnu", "--target-features=+aes,+sse2"]
X86_PCLMUL = [
    "--target-triple=x86_64-unknown-linux-gnu",
    "--target-features=+pclmul,+sse2",
]
GPU = ["--target-accelerator=sm_80"]

# (output name, source file, extra `mojo build` flags)
TARGETS = [
    ("aes_naive", "benchmarks/block_ciphers/aes/naive.mojo", []),
    ("aes_aarch64", "benchmarks/block_ciphers/aes/aarch64.mojo", AARCH64),
    ("aes_x86", "benchmarks/block_ciphers/aes/x86.mojo", X86_AES),
    ("aes_gpu", "benchmarks/block_ciphers/aes/gpu.mojo", GPU),
    ("ghash_naive", "benchmarks/universal_hashes/ghash/naive.mojo", []),
    ("ghash_aarch64", "benchmarks/universal_hashes/ghash/aarch64.mojo", AARCH64),
    ("ghash_x86", "benchmarks/universal_hashes/ghash/x86.mojo", X86_PCLMUL),
    ("polyval_naive", "benchmarks/universal_hashes/polyval/naive.mojo", []),
    ("polyval_aarch64", "benchmarks/universal_hashes/polyval/aarch64.mojo", AARCH64),
    ("polyval_x86", "benchmarks/universal_hashes/polyval/x86.mojo", X86_PCLMUL),
]


def main() -> int:
    with tempfile.TemporaryDirectory() as out:
        for name, source, flags in TARGETS:
            cmd = [
                "mojo",
                "build",
                "--emit=asm",
                *flags,
                "-I",
                ".",
                source,
                "-o",
                f"{out}/{name}",
            ]
            print(f"==> {name}", flush=True)
            if subprocess.run(cmd, cwd=ROOT).returncode != 0:
                print(f"failed to build {source}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
