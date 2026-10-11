from mojo_crypto.block_ciphers.aes import (
    AesAarch64,
    Aes128Aarch64,
    Aes192Aarch64,
    Aes256Aarch64,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES AArch64 benchmarks")

    @__parameter
    def aes[
        KeySize: Int
    ](key: Array[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
        return AesAarch64[KeySize](key)

    bench_cipher[Aes128Aarch64, 16, aes[16], "aes128"]()
    bench_cipher[Aes192Aarch64, 24, aes[24], "aes192"]()
    bench_cipher[Aes256Aarch64, 32, aes[32], "aes256"]()
