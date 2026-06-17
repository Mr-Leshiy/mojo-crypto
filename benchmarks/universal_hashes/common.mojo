from std.benchmark import run

from mojo_crypto.universal_hashes.traits import UniversalHashable

comptime BYTES_1K: Int = 1_024
comptime BYTES_16K: Int = 16_384


def bench_uhash[
    H: UniversalHashable & ImplicitlyDestructible,
    hash_init: def(InlineArray[UInt8, H.KEY_SIZE]) raises capturing[_] -> H,
    prefix: StringLiteral,
]() raises:
    var key = InlineArray[UInt8, H.KEY_SIZE](fill=0)

    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var data = InlineArray[UInt8, N](fill=0)

        @parameter
        def do_hash() raises:
            var hash = hash_init(key)
            hash.update(data)
            _ = hash^.finalize()

        run[do_hash]().print(prefix + "_" + suffix)

    bench[BYTES_1K, "1kb"]()
    bench[BYTES_16K, "16kb"]()
