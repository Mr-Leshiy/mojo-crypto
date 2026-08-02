from mojo_crypto.hashes.sha2 import (
    Sha224X86,
    Sha256X86,
    Sha384X86,
    Sha512X86,
    Sha512_224X86,
    Sha512_256X86,
)

from benchmarks.hashes.common import bench_hash


# Needs both x86 SHA-2 extensions enabled: +sha (SHA-NI, ubiquitous since AMD
# Zen 1 / Intel Ice Lake) for SHA-224/256, and +sha512 (Intel Arrow Lake /
# Lunar Lake and later) for SHA-384/512 and SHA-512/t. Without the latter the
# build fails outright with "LLVM ERROR: Cannot select: intrinsic
# %llvm.x86.vsha512rnds2" rather than falling back.
def main() raises:
    print("Running SHA-2 x86 benchmarks")

    bench_hash[Sha224X86, "sha224_x86"]()
    bench_hash[Sha256X86, "sha256_x86"]()
    bench_hash[Sha384X86, "sha384_x86"]()
    bench_hash[Sha512X86, "sha512_x86"]()
    bench_hash[Sha512_224X86, "sha512_224_x86"]()
    bench_hash[Sha512_256X86, "sha512_256_x86"]()
