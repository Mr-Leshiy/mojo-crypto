from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.hashes.traits import Digest
from mojo_crypto.hashes.sha2 import (
    Sha224Aarch64,
    Sha224Naive,
    Sha224X86,
    Sha256Aarch64,
    Sha256Naive,
    Sha256X86,
    Sha384Aarch64,
    Sha384Naive,
    Sha384X86,
    Sha512Aarch64,
    Sha512Naive,
    Sha512X86,
    Sha512_224Aarch64,
    Sha512_224Naive,
    Sha512_224X86,
    Sha512_256Aarch64,
    Sha512_256Naive,
    Sha512_256X86,
)

comptime DigestEngine = Digest & Movable & ImplicitlyDeletable
"""Bound every SHA-2 backend satisfies, and the one `check` is generic over."""


# Runs `check` once per SHA-2 backend the target can execute.
# The hardware backends need their crypto extension enabled at compile time:
# +sha2 for aarch64 SHA-224/256, +sha3 (ARMv8.2 SHA-512) for aarch64 SHA-384/512
# and SHA-512/t, +sha for x86 SHA-224/256, +sha512 for x86 SHA-384/512 and
# SHA-512/t (see .github/workflows/ci.yml for the per-runner feature sets).
#
# `x86` says whether the x86 backend is exercised at all. It is False for the
# 64-bit-word digests: their backend emits VSHA512* from the x86 SHA512
# extension, which no CI runner has (Intel Arrow Lake / Lunar Lake and later),
# and building it without +sha512 fails outright with "LLVM ERROR: Cannot
# select: intrinsic %llvm.x86.vsha512rnds2". Flip it to True on a CPU that has
# the extension to cover mojo_crypto/hashes/sha2/word64/x86.mojo locally.
def _run_sha2_checks[
    Naive: DigestEngine,
    Aarch64: DigestEngine,
    X86: DigestEngine,
    x86: Bool,
    TestInput: Copyable,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    comptime if target_triple_contains_any(["aarch64", "arm64"]):
        check[Aarch64](vectors)

    comptime if x86 and target_triple_contains_any(["x86_64"]):
        check[X86](vectors)

    check[Naive](vectors)


def run_sha224_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    _run_sha2_checks[
        Sha224Naive, Sha224Aarch64, Sha224X86, True, TestInput, check
    ](vectors)


def run_sha256_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    _run_sha2_checks[
        Sha256Naive, Sha256Aarch64, Sha256X86, True, TestInput, check
    ](vectors)


def run_sha384_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    _run_sha2_checks[
        Sha384Naive, Sha384Aarch64, Sha384X86, False, TestInput, check
    ](vectors)


def run_sha512_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    _run_sha2_checks[
        Sha512Naive, Sha512Aarch64, Sha512X86, False, TestInput, check
    ](vectors)


def run_sha512_224_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    _run_sha2_checks[
        Sha512_224Naive,
        Sha512_224Aarch64,
        Sha512_224X86,
        False,
        TestInput,
        check,
    ](vectors)


def run_sha512_256_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    _run_sha2_checks[
        Sha512_256Naive,
        Sha512_256Aarch64,
        Sha512_256X86,
        False,
        TestInput,
        check,
    ](vectors)
