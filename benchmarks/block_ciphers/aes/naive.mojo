from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    Aes128Naive,
    Aes192Naive,
    Aes256Naive,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES naive benchmarks")

    def aes[
        KeySize: Int
    ](key: Array[UInt8, KeySize]) raises -> AesNaive[KeySize]:
        return AesNaive[KeySize](key)

    bench_cipher["aes128"](aes[16])
    bench_cipher["aes192"](aes[24])
    bench_cipher["aes256"](aes[32])
