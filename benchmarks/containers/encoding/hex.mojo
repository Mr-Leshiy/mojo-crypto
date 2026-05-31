from std.benchmark import run

from mojo_crypto.containers.encoding import Hex

comptime BYTES_1K: Int = 1_024
comptime BYTES_4K: Int = 4_096
comptime BYTES_16K: Int = 16_384


def bench_hex[N: Int, suffix: StringLiteral]() raises:
    var data = List[UInt8](capacity=N)
    for i in range(N):
        data.append(UInt8(i % 256))

    var hex_str = Hex().encode(Span(data))

    @parameter
    def do_encode() raises:
        _ = Hex().encode(Span(data))

    @parameter
    def do_decode() raises:
        _ = Hex().decode(hex_str)

    run[do_encode]().print("hex_encode_" + suffix)
    run[do_decode]().print("hex_decode_" + suffix)


def main() raises:
    print("Running Hex encoding benchmarks")
    bench_hex[BYTES_1K, "1kb"]()
    bench_hex[BYTES_4K, "4kb"]()
    bench_hex[BYTES_16K, "16kb"]()
