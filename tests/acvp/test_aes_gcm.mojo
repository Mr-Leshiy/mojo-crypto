from std.testing import assert_equal, assert_raises, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.universal_hashes.ghash import GHashNaive
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.aead.gcm import Gcm

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import run_aes_checks


@fieldwise_init
struct GcmTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    # GCM nonce is variable length (commonly 12 bytes), so not a fixed array.
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]
    var aad: List[UInt8]
    # Authentication tag, possibly truncated (tagLen varies per group).
    var tag: List[UInt8]
    # For decrypt vectors: whether authentication is expected to succeed.
    var test_passed: Bool


def parse_acvp_aes_gcm_aft(
    python_vectors: PythonObject,
) raises -> List[GcmTestVector]:
    var vectors = List[GcmTestVector]()
    for v in python_vectors:
        group = v["group"]
        test = v["test"]
        expected = v["expected"]
        is_encrypt = String(group["direction"]) == "encrypt"

        # GCM carries the tag in the prompt on decrypt and in expectedResults
        # on encrypt; authentication failures are flagged via
        # testPassed=false, in which case expectedResults has no "pt".
        var pt_hex: String
        var ct_hex: String
        var tag_hex: String
        if is_encrypt:
            pt_hex = String(test["pt"])
            ct_hex = String(expected["ct"])
            tag_hex = String(expected["tag"])
        else:
            ct_hex = String(test["ct"])
            pt_hex = String(expected.get("pt", ""))
            tag_hex = String(test["tag"])

        vectors.append(
            GcmTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex_decode(String(test["key"])),
                iv=hex_decode(String(test["iv"])),
                pt=hex_decode(pt_hex),
                ct=hex_decode(ct_hex),
                aad=hex_decode(String(test["aad"])),
                tag=hex_decode(tag_hex),
                test_passed=expected.get("testPassed", True).__bool__(),
            )
        )
    return vectors^


def check_aes_gcm_aft[
    NONCE_SIZE: Int,
    TAG_SIZE: Int,
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[GcmTestVector]) raises:
    for v in vectors:
        # This instantiation only handles vectors matching its sizes; the GCM
        # set mixes several (key, nonce, tag) byte-length combinations.
        if (
            len(v.key) != KeySize
            or len(v.iv) != NONCE_SIZE
            or len(v.tag) != TAG_SIZE
        ):
            continue

        msg = "[Gcm[{}], nonce={}, tag={}], count={}".format(
            reflect[C]().name(), NONCE_SIZE, TAG_SIZE, v.count
        )
        key = to_inline_array[KeySize](v.key)
        nonce = to_inline_array[NONCE_SIZE](v.iv)
        tag = to_inline_array[TAG_SIZE](v.tag)
        if v.is_encrypt:
            data = v.pt.copy()
            gcm = Gcm[C, GHashNaive, NONCE_SIZE](cipher_init(key), nonce)
            actual_tag = gcm.encrypt[TAG_SIZE](v.aad[:], data[:])
            assert_equal(data, v.ct, msg=msg)
            assert_equal(actual_tag, tag, msg=msg)
        else:
            data = v.ct.copy()
            gcm = Gcm[C, GHashNaive, NONCE_SIZE](cipher_init(key), nonce)
            if v.test_passed:
                gcm.decrypt[TAG_SIZE](v.aad[:], data[:], tag)
                assert_equal(data, v.pt, msg=msg)
            else:
                with assert_raises():
                    gcm.decrypt[TAG_SIZE](v.aad[:], data[:], tag)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-GCM-1.0
# AES-GCM only defines AFT groups (no MCT).
def test_aes_gcm_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/ACVP-AES-GCM-1.0", "AFT"
    )
    var vectors = parse_acvp_aes_gcm_aft(raw)
    # The ACVP-AES-GCM-1.0 set uses two (nonce, tag) byte-size combinations.
    # `_` unbinds the remaining params (C, KeySize, cipher_init) for run_checks.
    run_aes_checks[GcmTestVector, check_aes_gcm_aft[12, 16, _, _, _]](vectors)
    run_aes_checks[GcmTestVector, check_aes_gcm_aft[15, 4, _, _, _]](vectors)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
