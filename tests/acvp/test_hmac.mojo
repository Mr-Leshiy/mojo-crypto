from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.macs import Hmac

from tests.acvp.utils import load_python_acvp_vectors
from tests.hashes.utils import (
    DigestEngine,
    run_sha224_checks,
    run_sha256_checks,
    run_sha384_checks,
    run_sha512_checks,
    run_sha512_224_checks,
    run_sha512_256_checks,
)


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


@__parameter
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
def test_hmac_sha224_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/HMAC-SHA2-224-1.0", "AFT"
    )
    run_sha224_checks[check_hmac_aft](parse_acvp_hmac_aft(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-256-1.0
def test_hmac_sha256_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/HMAC-SHA2-256-1.0", "AFT"
    )
    run_sha256_checks[check_hmac_aft](parse_acvp_hmac_aft(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-384-1.0
def test_hmac_sha384_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/HMAC-SHA2-384-1.0", "AFT"
    )
    run_sha384_checks[check_hmac_aft](parse_acvp_hmac_aft(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-1.0
def test_hmac_sha512_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/HMAC-SHA2-512-1.0", "AFT"
    )
    run_sha512_checks[check_hmac_aft](parse_acvp_hmac_aft(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-224-1.0
def test_hmac_sha512_224_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/HMAC-SHA2-512-224-1.0", "AFT"
    )
    run_sha512_224_checks[check_hmac_aft](parse_acvp_hmac_aft(raw))


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-256-1.0
def test_hmac_sha512_256_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/HMAC-SHA2-512-256-1.0", "AFT"
    )
    run_sha512_256_checks[check_hmac_aft](parse_acvp_hmac_aft(raw))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
