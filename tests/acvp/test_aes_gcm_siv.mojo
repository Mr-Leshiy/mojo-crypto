from std.testing import assert_equal, assert_raises, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.polyval import PolyvalCpu
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.aead.gcm_siv import GcmSiv

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import run_aes_checks


@fieldwise_init
struct GcmSivTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    # GCM-SIV ACVP vectors have no separate tag field: this is
    # ciphertext||tag (RFC 8452), split apart at check time.
    var ct: List[UInt8]
    var aad: List[UInt8]
    # For decrypt vectors: whether authentication is expected to succeed.
    var test_passed: Bool


def parse_acvp_aes_gcm_siv_aft(
    python_vectors: PythonObject,
) raises -> List[GcmSivTestVector]:
    var vectors = List[GcmSivTestVector]()
    hex = Hex()
    for v in python_vectors:
        group = v["group"]
        test = v["test"]
        expected = v["expected"]
        is_encrypt = String(group["direction"]) == "encrypt"

        var pt_hex: String
        var ct_hex: String
        if is_encrypt:
            pt_hex = String(test["pt"])
            ct_hex = String(expected["ct"])
        else:
            ct_hex = String(test["ct"])
            pt_hex = String(expected.get("pt", ""))

        vectors.append(
            GcmSivTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex.decode(String(test["key"])),
                iv=hex.decode(String(test["iv"])),
                pt=hex.decode(pt_hex),
                ct=hex.decode(ct_hex),
                aad=hex.decode(String(test["aad"])),
                test_passed=expected.get("testPassed", True).__bool__(),
            )
        )
    return vectors^


def check_aes_gcm_siv_aft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[GcmSivTestVector]) raises:
    # GCM-SIV (RFC 8452) fixes the nonce at 96 bits and the tag at 128 bits.
    comptime NONCE_SIZE = 12
    comptime TAG_SIZE = GcmSiv.TAG_SIZE

    for v in vectors:
        if (
            len(v.key) != KeySize
            or len(v.iv) != NONCE_SIZE
            or len(v.ct) < TAG_SIZE
        ):
            continue

        # GCM-SIV ACVP vectors have no separate tag field: the ciphertext is
        # ciphertext||tag (RFC 8452), so split the trailing TAG_SIZE bytes of
        # `v.ct` back out into the ciphertext body and the tag.
        cipher_len = len(v.ct) - TAG_SIZE
        cipher_body = List[UInt8](v.ct[:cipher_len])

        msg = "[GcmSiv[{}]], count={}".format(reflect[C]().name(), v.count)
        key = to_inline_array[KeySize](v.key)
        nonce = to_inline_array[NONCE_SIZE](v.iv)
        tag = to_inline_array[TAG_SIZE](List[UInt8](v.ct[cipher_len:]))
        if v.is_encrypt:
            data = v.pt.copy()
            gcm_siv = GcmSiv[C, PolyvalCpu].create[KeySize, cipher_init](
                key, nonce
            )
            actual_tag = gcm_siv.encrypt[TAG_SIZE](v.aad[:], data[:])
            assert_equal(data, cipher_body, msg=msg)
            assert_equal(actual_tag, tag, msg=msg)
        else:
            data = cipher_body.copy()
            gcm_siv = GcmSiv[C, PolyvalCpu].create[KeySize, cipher_init](
                key, nonce
            )
            if v.test_passed:
                gcm_siv.decrypt(v.aad[:], data[:], tag)
                assert_equal(data, v.pt, msg=msg)
            else:
                with assert_raises():
                    gcm_siv.decrypt(v.aad[:], data[:], tag)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-GCM-SIV-1.0
# AES-GCM-SIV only defines AFT groups (no MCT).
def test_aes_gcm_siv_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/ACVP-AES-GCM-SIV-1.0", "AFT"
    )
    run_aes_checks[GcmSivTestVector, check_aes_gcm_siv_aft](
        parse_acvp_aes_gcm_siv_aft(raw)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
