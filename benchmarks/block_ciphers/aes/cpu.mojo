from mojo_crypto.block_ciphers.aes import Aes, AesCpu

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES CPU benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> Aes[
        KeySize, AesCpu[KeySize]
    ]:
        return Aes[KeySize, AesCpu[KeySize]](AesCpu[KeySize](key))

    bench_cipher[Aes[16, AesCpu[16]], 16, aes[16], "aes128"]()
    bench_cipher[Aes[24, AesCpu[24]], 24, aes[24], "aes192"]()
    bench_cipher[Aes[32, AesCpu[32]], 32, aes[32], "aes256"]()
