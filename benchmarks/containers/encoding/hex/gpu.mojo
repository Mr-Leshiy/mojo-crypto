from std.gpu.host import DeviceContext

from mojo_crypto.containers.encoding.hex import HexGpu

from benchmarks.containers.encoding.hex.common import bench_hex


def main() raises:
    print("Running Hex GPU benchmarks")

    with DeviceContext() as ctx:

        @parameter
        def hex_gpu() raises -> HexGpu[]:
            return HexGpu(ctx)

        bench_hex[HexGpu[], hex_gpu, "hex_gpu"]()
