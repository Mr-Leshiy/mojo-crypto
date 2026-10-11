#!/usr/bin/env python3
"""Runs the Mojo test suite: every tests/**/test_*.mojo file, in sorted order.

Each file is built into a binary first and then run, rather than run with
`mojo run`: `assert_aborts` re-runs the test as a separate process, which needs
a compiled binary to re-run.

The hardware backends are compiled in only when their CPU features are enabled,
so the caller decides which ones to build via $MOJO_TEST_FEATURES: a
space-separated list of `mojo build` flags, e.g.
"--target-features=+neon,+aes,+sha2". CI sets it per-runner (see
.github/workflows/ci.yml). Nothing is defaulted here — when it is unset the
tests build for whatever `mojo build` autodetects on the host, which still
covers the naive backends.

Every test file that's run happens even if an earlier one fails; the failures
are listed again at the end.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    # Split on whitespace so several flags can be passed at once; an unset or
    # empty value yields no arguments at all.
    features = os.environ.get("MOJO_TEST_FEATURES", "").split()
    tests = sorted(ROOT.glob("tests/**/test_*.mojo"))
    if not tests:
        print("no tests/**/test_*.mojo files found", file=sys.stderr)
        return 1

    failed = []
    with tempfile.TemporaryDirectory() as build_dir:
        for test in tests:
            rel = test.relative_to(ROOT)
            binary = Path(build_dir) / "_".join(rel.with_suffix("").parts)
            build = [
                "mojo",
                "build",
                *features,
                "-I",
                ".",
                str(rel),
                "-o",
                str(binary),
            ]
            print(f"==> {' '.join(build)}", flush=True)
            if subprocess.run(build, cwd=ROOT).returncode != 0:
                failed.append(rel)
                continue
            print(f"==> {binary.name}", flush=True)
            if subprocess.run([str(binary)], cwd=ROOT).returncode != 0:
                failed.append(rel)

    if failed:
        print(f"\n{len(failed)} test file(s) failed:")
        for test in failed:
            print(f"  {test}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
