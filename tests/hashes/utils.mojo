from mojo_crypto.utils import target_triple_contains_any, has_target_feature
from mojo_crypto.hashes.traits import Digest

comptime DigestEngine = Digest & Movable & ImplicitlyDeletable
"""Bound every SHA-2 backend satisfies, and the one `check` is generic over."""


def run_sha224_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    from mojo_crypto.hashes.sha2 import Sha224Aarch64, Sha224Naive, Sha224X86

    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["sha2"]():
        check[Sha224Aarch64](vectors)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha"
    ]():
        check[Sha224X86](vectors)

    check[Sha224Naive](vectors)


def run_sha256_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    from mojo_crypto.hashes.sha2 import Sha256Aarch64, Sha256Naive, Sha256X86

    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["sha2"]():
        check[Sha256Aarch64](vectors)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha"
    ]():
        check[Sha256X86](vectors)

    check[Sha256Naive](vectors)


def run_sha384_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    from mojo_crypto.hashes.sha2 import Sha384Aarch64, Sha384Naive, Sha384X86

    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["sha3"]():
        check[Sha384Aarch64](vectors)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha512"
    ]():
        check[Sha384X86](vectors)

    check[Sha384Naive](vectors)


def run_sha512_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    from mojo_crypto.hashes.sha2 import Sha512Aarch64, Sha512Naive, Sha512X86

    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["sha3"]():
        check[Sha512Aarch64](vectors)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha512"
    ]():
        check[Sha512X86](vectors)

    check[Sha512Naive](vectors)


def run_sha512_224_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    from mojo_crypto.hashes.sha2 import (
        Sha512_224Aarch64,
        Sha512_224Naive,
        Sha512_224X86,
    )

    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["sha3"]():
        check[Sha512_224Aarch64](vectors)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha512"
    ]():
        check[Sha512_224X86](vectors)

    check[Sha512_224Naive](vectors)


def run_sha512_256_checks[
    TestInput: Copyable,
    //,
    check: def[T: DigestEngine](TestInput) raises capturing[_],
](vectors: TestInput) raises:
    from mojo_crypto.hashes.sha2 import (
        Sha512_256Aarch64,
        Sha512_256Naive,
        Sha512_256X86,
    )

    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["sha3"]():
        check[Sha512_256Aarch64](vectors)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha512"
    ]():
        check[Sha512_256X86](vectors)

    check[Sha512_256Naive](vectors)
