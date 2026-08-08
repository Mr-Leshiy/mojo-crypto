from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    Aes128Naive,
    Aes192Naive,
    Aes256Naive,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES naive benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: Array[UInt8, KeySize]) raises -> AesNaive[KeySize]:
        return AesNaive[KeySize](key)

    bench_cipher[Aes128Naive, 16, aes[16], "aes128"]()
    bench_cipher[Aes192Naive, 24, aes[24], "aes192"]()
    bench_cipher[Aes256Naive, 32, aes[32], "aes256"]()
