from std.benchmark import run

from mojo_crypto.universal_hashes.polyval.cpu import PolyvalCpu
from mojo_crypto.universal_hashes.polyval.common import KEY_SIZE

comptime BYTES_1K: Int = 1_024
comptime BYTES_16K: Int = 16_384


def main() raises:
    print("Running POLYVAL CPU benchmarks")

    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var key = InlineArray[UInt8, KEY_SIZE](fill=0)
        var data = InlineArray[UInt8, N](fill=0)

        @parameter
        def do_hash() raises:
            var poly = PolyvalCpu(key)
            poly.update(data)
            _ = poly^.finalize()

        run[do_hash]().print("polyval_cpu_" + suffix)

    bench[BYTES_1K, "1kb"]()
    bench[BYTES_16K, "16kb"]()
