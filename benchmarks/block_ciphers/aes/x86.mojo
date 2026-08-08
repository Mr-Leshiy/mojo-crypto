from mojo_crypto.block_ciphers.aes import (
    AesX86,
    Aes128X86,
    Aes192X86,
    Aes256X86,
)

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES x86 AES-NI benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: Array[UInt8, KeySize]) raises -> AesX86[KeySize]:
        return AesX86[KeySize](key)

    bench_cipher[Aes128X86, 16, aes[16], "aes128"]()
    bench_cipher[Aes192X86, 24, aes[24], "aes192"]()
    bench_cipher[Aes256X86, 32, aes[32], "aes256"]()
