from std.benchmark import run

from mojo_crypto.universal_hashes.ghash.cpu import GHashCpu
from mojo_crypto.universal_hashes.ghash.common import KEY_SIZE

comptime BYTES_1K: Int = 1_024
comptime BYTES_16K: Int = 16_384


def main() raises:
    print("Running GHASH CPU benchmarks")

    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var key = InlineArray[UInt8, KEY_SIZE](fill=0)
        var data = InlineArray[UInt8, N](fill=0)

        @parameter
        def do_hash() raises:
            var ghash = GHashCpu(key)
            ghash.update(data)
            _ = ghash.finalize()

        run[do_hash]().print("ghash_cpu_" + suffix)

    bench[BYTES_1K, "1kb"]()
    bench[BYTES_16K, "16kb"]()
