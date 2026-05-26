from mojo_crypto.aes import Aes, AesArmv8Backend

from benchmarks.aes.common import bench_cipher


def main() raises:
    print("Running AES ARMv8 benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize, AesArmv8Backend[KeySize]]:
        return Aes[KeySize, AesArmv8Backend[KeySize]](AesArmv8Backend[KeySize](key))

    bench_cipher[Aes[16, AesArmv8Backend[16]], 16, aes[16], "aes128"]()
    bench_cipher[Aes[24, AesArmv8Backend[24]], 24, aes[24], "aes192"]()
    bench_cipher[Aes[32, AesArmv8Backend[32]], 32, aes[32], "aes256"]()
