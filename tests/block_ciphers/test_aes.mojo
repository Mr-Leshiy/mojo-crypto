from std.testing import assert_equal, TestSuite
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)

from tests.block_ciphers.utils import run_aes_checks


@fieldwise_init
struct AesTestVector(Copyable, Movable):
    var key: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


def check_aes[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[AesTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[{}], key_size={}".format(reflect[C]().name(), KeySize)

        var cipher = cipher_init(to_inline_array[KeySize](v.key))

        var pt = v.pt.copy()
        cipher.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        cipher.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


# Single-block known-answer vectors for AES-128/192/256, from FIPS 197
# Appendix B (AES-128) / Appendix C (AES-128/192/256), also reproduced as
# RustCrypto's `aes` crate hazmat test vectors:
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
# https://github.com/RustCrypto/block-ciphers/blob/master/aes/tests/hazmat.rs
def test_aes_fips197_kat() raises:
    var hex = Hex()
    var vectors: List[AesTestVector] = [
        AesTestVector(
            key=hex.decode("000102030405060708090a0b0c0d0e0f"),
            pt=hex.decode("00112233445566778899aabbccddeeff"),
            ct=hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
        AesTestVector(
            key=hex.decode(
                "000102030405060708090a0b0c0d0e0f1011121314151617"
            ),
            pt=hex.decode("00112233445566778899aabbccddeeff"),
            ct=hex.decode("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
        AesTestVector(
            key=hex.decode(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            ),
            pt=hex.decode("00112233445566778899aabbccddeeff"),
            ct=hex.decode("8ea2b7ca516745bfeafc49904b496089"),
        ),
    ]
    run_aes_checks[AesTestVector, check_aes](vectors)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
