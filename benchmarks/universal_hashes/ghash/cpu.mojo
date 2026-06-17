from mojo_crypto.universal_hashes.ghash.cpu import GHashCpu
from mojo_crypto.universal_hashes.ghash.common import KEY_SIZE

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running GHASH CPU benchmarks")

    @parameter
    def ghash(key: InlineArray[UInt8, KEY_SIZE]) raises -> GHashCpu:
        return GHashCpu(key)

    bench_uhash[GHashCpu, ghash, "ghash_cpu"]()
