from mojo_crypto.containers.encoding.hex import HexCpu

from benchmarks.containers.encoding.hex.common import bench_hex


def main() raises:
    print("Running Hex CPU benchmarks")

    @parameter
    def hex_cpu() raises -> HexCpu:
        return HexCpu()

    bench_hex[HexCpu, hex_cpu, "hex_cpu"]()
