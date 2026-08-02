from mojo_crypto.hashes.sha2 import (
    Sha224Naive,
    Sha256Naive,
    Sha384Naive,
    Sha512Naive,
    Sha512_224Naive,
    Sha512_256Naive,
)

from benchmarks.hashes.common import bench_hash


def main() raises:
    print("Running SHA-2 naive benchmarks")

    bench_hash[Sha224Naive, "sha224_naive"]()
    bench_hash[Sha256Naive, "sha256_naive"]()
    bench_hash[Sha384Naive, "sha384_naive"]()
    bench_hash[Sha512Naive, "sha512_naive"]()
    bench_hash[Sha512_224Naive, "sha512_224_naive"]()
    bench_hash[Sha512_256Naive, "sha512_256_naive"]()
