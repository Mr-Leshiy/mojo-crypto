from mojo_crypto.hashes.sha2 import (
    Sha224Aarch64,
    Sha256Aarch64,
    Sha384Aarch64,
    Sha512Aarch64,
    Sha512_224Aarch64,
    Sha512_256Aarch64,
)

from benchmarks.hashes.common import bench_hash


# Needs both AArch64 SHA-2 extensions enabled: +sha2 for the SHA-256
# instructions (SHA-224/256) and +sha3 for the ARMv8.2 SHA-512 ones
# (SHA-384/512 and SHA-512/t).
def main() raises:
    print("Running SHA-2 AArch64 benchmarks")

    bench_hash[Sha224Aarch64, "sha224_aarch64"]()
    bench_hash[Sha256Aarch64, "sha256_aarch64"]()
    bench_hash[Sha384Aarch64, "sha384_aarch64"]()
    bench_hash[Sha512Aarch64, "sha512_aarch64"]()
    bench_hash[Sha512_224Aarch64, "sha512_224_aarch64"]()
    bench_hash[Sha512_256Aarch64, "sha512_256_aarch64"]()
