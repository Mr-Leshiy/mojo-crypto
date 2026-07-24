from mojo_crypto.block_ciphers.aes import AesNaive

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES naive benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesNaive[KeySize]:
        return AesNaive[KeySize](key)

    bench_cipher[AesNaive[16], 16, aes[16], "aes128"]()
    bench_cipher[AesNaive[24], 24, aes[24], "aes192"]()
    bench_cipher[AesNaive[32], 32, aes[32], "aes256"]()
