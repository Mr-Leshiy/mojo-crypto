from mojo_crypto.universal_hashes.ghash import GHashAarch64

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running GHASH AArch64 benchmarks")

    bench_uhash[GHashAarch64, "ghash_aarch64"]()
