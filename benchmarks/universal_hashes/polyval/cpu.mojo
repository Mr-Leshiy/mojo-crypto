from mojo_crypto.universal_hashes.polyval import PolyvalCpu

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running POLYVAL CPU benchmarks")

    bench_uhash[PolyvalCpu, "polyval_cpu"]()
