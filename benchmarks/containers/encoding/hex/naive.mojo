from mojo_crypto.containers.encoding.hex import Hex

from benchmarks.containers.encoding.hex.common import bench_hex


def main() raises:
    print("Running Hex naive benchmarks")

    @parameter
    def hex_naive() raises -> Hex:
        return Hex()

    bench_hex[Hex, hex_naive, "hex_naive"]()
