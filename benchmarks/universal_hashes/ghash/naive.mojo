from mojo_crypto.universal_hashes.ghash import GHashNaive

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running GHASH naive benchmarks")

    bench_uhash[GHashNaive, "ghash_naive"]()
