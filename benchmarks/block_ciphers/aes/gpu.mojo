from max.gpu.host import DeviceContext

from mojo_crypto.block_ciphers.aes import (
    AesGpu,
    Aes128Gpu,
    Aes192Gpu,
    Aes256Gpu,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES GPU benchmarks")

    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: Array[UInt8, KeySize]) raises -> AesGpu[KeySize]:
            return AesGpu[KeySize](ctx, key)

        bench_cipher[Aes128Gpu, 16, aes[16], "aes128"]()
        bench_cipher[Aes192Gpu, 24, aes[24], "aes192"]()
        bench_cipher[Aes256Gpu, 32, aes[32], "aes256"]()
