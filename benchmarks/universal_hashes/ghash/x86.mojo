from mojo_crypto.universal_hashes.ghash import GHashX86

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running GHASH x86 PCLMULQDQ benchmarks")

    bench_uhash[GHashX86, "ghash_x86"]()
