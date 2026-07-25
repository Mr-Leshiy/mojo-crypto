from mojo_crypto.universal_hashes.polyval import PolyvalNaive

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running POLYVAL naive benchmarks")

    bench_uhash[PolyvalNaive, "polyval_naive"]()
