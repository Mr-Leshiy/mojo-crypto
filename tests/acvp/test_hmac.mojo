from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.macs import Hmac
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
from mojo_crypto.hashes.sha3 import (
    Sha3_224Naive,
    Sha3_256Naive,
    Sha3_384Naive,
    Sha3_512Naive,
)

from tests.acvp.utils import load_python_acvp_vectors
from tests.hashes.utils import DigestEngine
from tests.platform import register_platform_tests


@fieldwise_init
struct HmacTestVector(Copyable, Movable):
    var count: Int
    var key: List[UInt8]
    var msg: List[UInt8]
    # Expected tag, possibly truncated (macLen varies per group).
    var mac: List[UInt8]


def parse_acvp_hmac_aft(
    python_vectors: PythonObject,
) raises -> List[HmacTestVector]:
    var vectors = List[HmacTestVector]()
    for v in python_vectors:
        var test = v["test"]
        var expected = v["expected"]

        # Unlike the SHA-2 sets, no bit-granular lengths to skip: the HMAC
        # registration pins keyLen, msgLen and macLen to increments of 8.
        #
        # mac_hex is left at whatever length the JSON gives, so the check
        # derives the truncation from len(mac) rather than a separate field.
        vectors.append(
            HmacTestVector(
                count=Int(py=test["tcId"]),
                key=hex_decode(String(test["key"])),
                msg=hex_decode(String(test["msg"])),
                mac=hex_decode(String(expected["mac"])),
            )
        )
    return vectors^


def check_hmac_aft[T: DigestEngine](vectors: List[HmacTestVector]) raises:
    for v in vectors:
        var msg = "[Hmac[{}]], count={}".format(reflect[T].name(), v.count)

        var hmac = Hmac[T](Span(v.key))
        hmac.update(Span(v.msg))
        var full_tag = hmac^.finalize()

        # ACVP HMAC vectors specify a MAC truncated below the digest (80..160
        # bits, against a 224-bit digest at the narrowest); v.mac is already
        # decoded at that length, so only compare that many leading bytes of
        # our computed tag.
        var actual_mac = List[UInt8](capacity=len(v.mac))
        for i in range(len(v.mac)):
            actual_mac.append(full_tag[i])

        assert_equal(actual_mac, v.mac, msg=msg)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-224-1.0
# HMAC only defines AFT groups (no MCT). Keys run 8..2048 bits, so both key
# paths are covered: shorter than the block (zero-padded) and longer than it
# (hashed down first).
def test_hmac_sha224_aft_naive() raises:
    check_hmac_aft[Sha224Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-224", "AFT"))
    )


def test_hmac_sha224_aft_aarch64() raises:
    check_hmac_aft[Sha224Aarch64](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-224", "AFT"))
    )


def test_hmac_sha224_aft_x86() raises:
    check_hmac_aft[Sha224X86](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-224", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-256-1.0
def test_hmac_sha256_aft_naive() raises:
    check_hmac_aft[Sha256Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-256", "AFT"))
    )


def test_hmac_sha256_aft_aarch64() raises:
    check_hmac_aft[Sha256Aarch64](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-256", "AFT"))
    )


def test_hmac_sha256_aft_x86() raises:
    check_hmac_aft[Sha256X86](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-256", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-384-1.0
def test_hmac_sha384_aft_naive() raises:
    check_hmac_aft[Sha384Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-384", "AFT"))
    )


def test_hmac_sha384_aft_aarch64() raises:
    check_hmac_aft[Sha384Aarch64](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-384", "AFT"))
    )


def test_hmac_sha384_aft_x86() raises:
    check_hmac_aft[Sha384X86](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-384", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-1.0
def test_hmac_sha512_aft_naive() raises:
    check_hmac_aft[Sha512Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-512", "AFT"))
    )


def test_hmac_sha512_aft_aarch64() raises:
    check_hmac_aft[Sha512Aarch64](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-512", "AFT"))
    )


def test_hmac_sha512_aft_x86() raises:
    check_hmac_aft[Sha512X86](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA2-512", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-224-1.0
def test_hmac_sha512_224_aft_naive() raises:
    check_hmac_aft[Sha512_224Naive](
        parse_acvp_hmac_aft(
            load_python_acvp_vectors("HMAC-SHA2-512-224", "AFT")
        )
    )


def test_hmac_sha512_224_aft_aarch64() raises:
    check_hmac_aft[Sha512_224Aarch64](
        parse_acvp_hmac_aft(
            load_python_acvp_vectors("HMAC-SHA2-512-224", "AFT")
        )
    )


def test_hmac_sha512_224_aft_x86() raises:
    check_hmac_aft[Sha512_224X86](
        parse_acvp_hmac_aft(
            load_python_acvp_vectors("HMAC-SHA2-512-224", "AFT")
        )
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-256-1.0
def test_hmac_sha512_256_aft_naive() raises:
    check_hmac_aft[Sha512_256Naive](
        parse_acvp_hmac_aft(
            load_python_acvp_vectors("HMAC-SHA2-512-256", "AFT")
        )
    )


def test_hmac_sha512_256_aft_aarch64() raises:
    check_hmac_aft[Sha512_256Aarch64](
        parse_acvp_hmac_aft(
            load_python_acvp_vectors("HMAC-SHA2-512-256", "AFT")
        )
    )


def test_hmac_sha512_256_aft_x86() raises:
    check_hmac_aft[Sha512_256X86](
        parse_acvp_hmac_aft(
            load_python_acvp_vectors("HMAC-SHA2-512-256", "AFT")
        )
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA3-224-2.0
# Same AFT-only shape as the HMAC-SHA2 sets (parse_acvp_hmac_aft doesn't
# reference algorithm-specific fields), just against `-2.0` (see README for
# why `-2.0` over `-1.0`).
def test_hmac_sha3_224_aft_naive() raises:
    check_hmac_aft[Sha3_224Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA3-224", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA3-256-2.0
def test_hmac_sha3_256_aft_naive() raises:
    check_hmac_aft[Sha3_256Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA3-256", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA3-384-2.0
def test_hmac_sha3_384_aft_naive() raises:
    check_hmac_aft[Sha3_384Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA3-384", "AFT"))
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA3-512-2.0
def test_hmac_sha3_512_aft_naive() raises:
    check_hmac_aft[Sha3_512Naive](
        parse_acvp_hmac_aft(load_python_acvp_vectors("HMAC-SHA3-512", "AFT"))
    )


def main() raises:
    var suite = TestSuite()
    register_platform_tests[__functions_in_module()](suite)
    suite^.run()
