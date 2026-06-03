from std.gpu.host import DeviceContext

from mojo_crypto.block_ciphers.aes import AesGpu

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES GPU benchmarks")

    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesGpu[KeySize]:
            return AesGpu[KeySize](ctx, key)

        bench_cipher[AesGpu[16], 16, aes[16], "aes128"]()
        bench_cipher[AesGpu[24], 24, aes[24], "aes192"]()
        bench_cipher[AesGpu[32], 32, aes[32], "aes256"]()
