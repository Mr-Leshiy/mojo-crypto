from mojo_crypto.block_ciphers.aes import Aes, AesX86

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES x86 AES-NI benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, AesX86[KeySize]
    ]:
        return Aes[KeySize, AesX86[KeySize]](AesX86[KeySize](key))

    bench_cipher[Aes[16, AesX86[16]], 16, aes[16], "aes128"]()
    bench_cipher[Aes[24, AesX86[24]], 24, aes[24], "aes192"]()
    bench_cipher[Aes[32, AesX86[32]], 32, aes[32], "aes256"]()
