from mojo_crypto.aes import Aes, AesX86Backend

from benchmarks.aes.common import bench_cipher


def main() raises:
    print("Running AES x86 AES-NI benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, AesX86Backend[KeySize]
    ]:
        return Aes[KeySize, AesX86Backend[KeySize]](AesX86Backend[KeySize](key))

    bench_cipher[Aes[16, AesX86Backend[16]], 16, aes[16], "aes128"]()
    bench_cipher[Aes[24, AesX86Backend[24]], 24, aes[24], "aes192"]()
    bench_cipher[Aes[32, AesX86Backend[32]], 32, aes[32], "aes256"]()
