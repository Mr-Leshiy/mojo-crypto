from mojo_crypto.containers.encoding.hex import Hex

from benchmarks.containers.encoding.hex.common import bench_hex


def main() raises:
    print("Running Hex CPU benchmarks")

    @parameter
    def hex_cpu() raises -> Hex:
        return Hex()

    bench_hex[Hex, hex_cpu, "hex_cpu"]()
