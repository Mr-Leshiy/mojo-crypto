from mojo_crypto.block_ciphers.aes import (
    AesAarch64,
    Aes128Aarch64,
    Aes192Aarch64,
    Aes256Aarch64,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES AArch64 benchmarks")

    def aes[
        KeySize: Int
    ](key: Array[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
        return AesAarch64[KeySize](key)

    bench_cipher["aes128"](aes[16])
    bench_cipher["aes192"](aes[24])
    bench_cipher["aes256"](aes[32])
