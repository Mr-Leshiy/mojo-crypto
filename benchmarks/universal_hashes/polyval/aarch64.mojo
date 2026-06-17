from mojo_crypto.universal_hashes.polyval import PolyvalAarch64

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running POLYVAL AArch64 benchmarks")

    bench_uhash[PolyvalAarch64, "polyval_aarch64"]()
