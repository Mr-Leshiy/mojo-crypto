from mojo_crypto.block_ciphers.aes import AesCpu

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES CPU benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesCpu[KeySize]:
        return AesCpu[KeySize](key)

    bench_cipher[AesCpu[16], 16, aes[16], "aes128"]()
    bench_cipher[AesCpu[24], 24, aes[24], "aes192"]()
    bench_cipher[AesCpu[32], 32, aes[32], "aes256"]()
