from mojo_crypto.block_ciphers.aes import Aes, AesCpuBackend

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES CPU benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, AesCpuBackend[KeySize]
    ]:
        return Aes[KeySize, AesCpuBackend[KeySize]](AesCpuBackend[KeySize](key))

    bench_cipher[Aes[16, AesCpuBackend[16]], 16, aes[16], "aes128"]()
    bench_cipher[Aes[24, AesCpuBackend[24]], 24, aes[24], "aes192"]()
    bench_cipher[Aes[32, AesCpuBackend[32]], 32, aes[32], "aes256"]()
