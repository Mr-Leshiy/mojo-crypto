from mojo_crypto.universal_hashes.polyval import PolyvalX86

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running POLYVAL x86 PCLMULQDQ benchmarks")

    bench_uhash[PolyvalX86, "polyval_x86"]()
