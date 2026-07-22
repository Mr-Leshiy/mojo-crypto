from std.testing import TestSuite

from mojo_crypto.hashes import Sha256, Sha384, Sha512

from tests.hashes.utils import check_hash


# Test vectors from FIPS 180-2 Appendix B (SHA-256 Examples):
# https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf
def test_sha256_fips180_2_vectors() raises:
    # B.1 — one-block message.
    check_hash[Sha256](
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    # B.2 — multi-block message.
    check_hash[Sha256](
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )
    # B.3 — long message: 1,000,000 repetitions of "a".
    check_hash[Sha256](
        String("a" * 1_000_000),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )


# Test vectors from FIPS 180-2 Appendix D (SHA-384 Examples):
# https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf
def test_sha384_fips180_2_vectors() raises:
    # D.1 — one-block message.
    check_hash[Sha384](
        "abc",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )
    # D.2 — multi-block message.
    check_hash[Sha384](
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    )
    # D.3 — long message: 1,000,000 repetitions of "a".
    check_hash[Sha384](
        String("a" * 1_000_000),
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
    )


# Test vectors from FIPS 180-2 Appendix C (SHA-512 Examples):
# https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf
def test_sha512_fips180_2_vectors() raises:
    # C.1 — one-block message.
    check_hash[Sha512](
        "abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )
    # C.2 — multi-block message.
    check_hash[Sha512](
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    )
    # C.3 — long message: 1,000,000 repetitions of "a".
    check_hash[Sha512](
        String("a" * 1_000_000),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
