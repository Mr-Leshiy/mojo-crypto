from mojo_crypto.block_ciphers.aes import AesAarch64

from benchmarks.block_ciphers.aes.common import bench_cipher


def main() raises:
    print("Running AES AArch64 benchmarks")

    @parameter
    def aes[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
        return AesAarch64[KeySize](key)

    bench_cipher[AesAarch64[16], 16, aes[16], "aes128"]()
    bench_cipher[AesAarch64[24], 24, aes[24], "aes192"]()
    bench_cipher[AesAarch64[32], 32, aes[32], "aes256"]()
