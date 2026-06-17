from mojo_crypto.universal_hashes.polyval.cpu import PolyvalCpu
from mojo_crypto.universal_hashes.polyval.common import KEY_SIZE

from benchmarks.universal_hashes.common import bench_uhash


def main() raises:
    print("Running POLYVAL CPU benchmarks")

    @parameter
    def polyval(key: InlineArray[UInt8, KEY_SIZE]) raises -> PolyvalCpu:
        return PolyvalCpu(key)

    bench_uhash[PolyvalCpu, polyval, "polyval_cpu"]()
