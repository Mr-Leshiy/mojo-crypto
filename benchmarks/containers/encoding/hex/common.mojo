from std.benchmark import run

from mojo_crypto.containers.encoding.traits import Encodable, Decodable

comptime BYTES_1K: Int = 1_024
comptime BYTES_4K: Int = 4_096
comptime BYTES_16K: Int = 16_384


def bench_hex[
    H: Encodable & Decodable & ImplicitlyDestructible & Movable,
    hex_init: def() raises capturing[_] -> H,
    prefix: StringLiteral,
]() raises:
    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var data = List[UInt8](capacity=N)
        for i in range(N):
            data.append(UInt8(i % 256))
        var hex_str = hex_init().encode(Span(data))

        @parameter
        def do_encode() raises:
            _ = hex_init().encode(Span(data))

        @parameter
        def do_decode() raises:
            _ = hex_init().decode(hex_str)

        run[do_encode]().print(prefix + "_encode_" + suffix)
        run[do_decode]().print(prefix + "_decode_" + suffix)

    bench[BYTES_1K, "1kb"]()
    bench[BYTES_4K, "4kb"]()
    bench[BYTES_16K, "16kb"]()
