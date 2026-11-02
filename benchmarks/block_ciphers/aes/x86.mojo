from mojo_crypto.block_ciphers.aes import (
    AesX86,
    Aes128X86,
    Aes192X86,
    Aes256X86,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES x86 AES-NI benchmarks")

    def aes[KeySize: Int](key: Array[UInt8, KeySize]) raises -> AesX86[KeySize]:
        return AesX86[KeySize](key)

    bench_cipher["aes128"](aes[16])
    bench_cipher["aes192"](aes[24])
    bench_cipher["aes256"](aes[32])
