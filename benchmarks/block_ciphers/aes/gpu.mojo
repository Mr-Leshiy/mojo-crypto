from std.gpu.host import DeviceContext

from mojo_crypto.block_ciphers.aes import Aes, AesCpuBackend, AesGpuBackend

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES GPU benchmarks")

    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
            KeySize, AesGpuBackend
        ]:
            return Aes[KeySize, AesGpuBackend](
                AesGpuBackend(ctx, AesCpuBackend[KeySize](key).w)
            )

        bench_cipher[Aes[16, AesGpuBackend], 16, aes[16], "aes128"]()
        bench_cipher[Aes[24, AesGpuBackend], 24, aes[24], "aes192"]()
        bench_cipher[Aes[32, AesGpuBackend], 32, aes[32], "aes256"]()
