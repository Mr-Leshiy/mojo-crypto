from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.hashes.traits import Digest
from mojo_crypto.hashes.sha2 import (
    Sha224Aarch64,
    Sha224Naive,
    Sha256Aarch64,
    Sha256Naive,
    Sha384Aarch64,
    Sha384Naive,
    Sha512Aarch64,
    Sha512Naive,
    Sha512_224Aarch64,
    Sha512_224Naive,
    Sha512_256Aarch64,
    Sha512_256Naive,
)

comptime DigestEngine = Digest & Movable & ImplicitlyDeletable
"""Bound every SHA-2 backend satisfies, and the one `check` is generic over."""


# Runs `check` once per SHA-2 backend the target can execute.
# The aarch64 backends need their crypto extension enabled at compile time:
# +sha2 for SHA-224/256, +sha3 (ARMv8.2 SHA-512) for SHA-384/512 and SHA-512/t.
def _run_sha2_checks[
    Naive: DigestEngine,
    Aarch64: DigestEngine,
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    comptime if target_triple_contains_any(["aarch64", "arm64"]):
        check[Aarch64](vectors)

    check[Naive](vectors)


def run_sha224_checks[
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    _run_sha2_checks[Sha224Naive, Sha224Aarch64, TestVector, check](vectors)


def run_sha256_checks[
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    _run_sha2_checks[Sha256Naive, Sha256Aarch64, TestVector, check](vectors)


def run_sha384_checks[
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    _run_sha2_checks[Sha384Naive, Sha384Aarch64, TestVector, check](vectors)


def run_sha512_checks[
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    _run_sha2_checks[Sha512Naive, Sha512Aarch64, TestVector, check](vectors)


def run_sha512_224_checks[
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    _run_sha2_checks[Sha512_224Naive, Sha512_224Aarch64, TestVector, check](
        vectors
    )


def run_sha512_256_checks[
    TestVector: Copyable,
    check: def[T: DigestEngine](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    _run_sha2_checks[Sha512_256Naive, Sha512_256Aarch64, TestVector, check](
        vectors
    )
