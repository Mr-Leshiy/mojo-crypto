from mojo_crypto.universal_hashes.polyval.aarch64 import PolyvalAarch64
from mojo_crypto.universal_hashes.polyval.common import KEY_SIZE

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running POLYVAL AArch64 benchmarks")

    @parameter
    def polyval(key: InlineArray[UInt8, KEY_SIZE]) raises -> PolyvalAarch64:
        return PolyvalAarch64(key)

    bench_uhash[PolyvalAarch64, polyval, "polyval_aarch64"]()
