from mojo_crypto.universal_hashes.ghash import GHashCpu

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running GHASH CPU benchmarks")

    bench_uhash[GHashCpu, "ghash_cpu"]()
