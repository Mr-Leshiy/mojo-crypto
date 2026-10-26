from std.testing import assert_equal, assert_raises, TestSuite
from std.python import PythonObject
from max.gpu.host import DeviceContext
from std.reflection import reflect

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.universal_hashes.polyval import PolyvalNaive
from mojo_crypto.aead.gcm_siv import GcmSiv

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import (
    AesFactory,
    AesAarch64Factory,
    AesGpuFactory,
    AesNaiveFactory,
    AesX86Factory,
)
from tests.platform import HAS_AES_AARCH64, HAS_AES_X86, HAS_GPU


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
    for v in python_vectors:
        var group = v["group"]
        var test = v["test"]
        var expected = v["expected"]
        var is_encrypt = String(group["direction"]) == "encrypt"

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
                key=hex_decode(String(test["key"])),
                iv=hex_decode(String(test["iv"])),
                pt=hex_decode(pt_hex),
                ct=hex_decode(ct_hex),
                aad=hex_decode(String(test["aad"])),
                test_passed=expected.get("testPassed", True).__bool__(),
            )
        )
    return vectors^


def check_aes_gcm_siv_aft[
    F: AesFactory
](factory: F, vectors: List[GcmSivTestVector]) raises:
    # GCM-SIV (RFC 8452) fixes the nonce at 96 bits and the tag at 128 bits.
    comptime NONCE_SIZE = 12
    comptime TAG_SIZE = GcmSiv.TAG_SIZE

    # GCM-SIV derives its subkeys through a fresh cipher, so it takes a cipher
    # constructor rather than a cipher.
    @__parameter
    def cipher_init(key: Array[UInt8, F.KEY_SIZE]) raises -> F.Cipher:
        return factory.create(key)

    for v in vectors:
        if (
            len(v.key) != F.KEY_SIZE
            or len(v.iv) != NONCE_SIZE
            or len(v.ct) < TAG_SIZE
        ):
            continue

        # GCM-SIV ACVP vectors have no separate tag field: the ciphertext is
        # ciphertext||tag (RFC 8452), so split the trailing TAG_SIZE bytes of
        # `v.ct` back out into the ciphertext body and the tag.
        var cipher_len = len(v.ct) - TAG_SIZE
        var cipher_body = List[UInt8](v.ct[:cipher_len])

        var msg = "[GcmSiv[{}]], count={}".format(
            reflect[F.Cipher].name(), v.count
        )
        var key = to_array[F.KEY_SIZE](v.key)
        var nonce = to_array[NONCE_SIZE](v.iv)
        var tag = to_array[TAG_SIZE](List[UInt8](v.ct[cipher_len:]))
        if v.is_encrypt:
            var data = v.pt.copy()
            var gcm_siv = GcmSiv[F.Cipher, PolyvalNaive].create[
                F.KEY_SIZE, cipher_init
            ](key, nonce)
            var actual_tag = gcm_siv.encrypt[TAG_SIZE](v.aad[:], data[:])
            assert_equal(data, cipher_body, msg=msg)
            assert_equal(actual_tag, tag, msg=msg)
        else:
            var data = cipher_body.copy()
            var gcm_siv = GcmSiv[F.Cipher, PolyvalNaive].create[
                F.KEY_SIZE, cipher_init
            ](key, nonce)
            if v.test_passed:
                gcm_siv.decrypt(v.aad[:], data[:], tag)
                assert_equal(data, v.pt, msg=msg)
            else:
                with assert_raises():
                    gcm_siv.decrypt(v.aad[:], data[:], tag)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-GCM-SIV-1.0
# AES-GCM-SIV only defines AFT groups (no MCT). The registration covers
# AES-128 only.
def aes_gcm_siv_aft_vectors() raises -> List[GcmSivTestVector]:
    return parse_acvp_aes_gcm_siv_aft(
        load_python_acvp_vectors("ACVP-AES-GCM-SIV", "AFT")
    )


def test_aes128_gcm_siv_aft_naive() raises:
    check_aes_gcm_siv_aft(AesNaiveFactory[16](), aes_gcm_siv_aft_vectors())


def test_aes128_gcm_siv_aft_aarch64() raises:
    check_aes_gcm_siv_aft(AesAarch64Factory[16](), aes_gcm_siv_aft_vectors())


def test_aes128_gcm_siv_aft_x86() raises:
    check_aes_gcm_siv_aft(AesX86Factory[16](), aes_gcm_siv_aft_vectors())


def test_aes128_gcm_siv_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_gcm_siv_aft(AesGpuFactory[16](ctx), aes_gcm_siv_aft_vectors())


def main() raises:
    var suite = TestSuite()

    suite.test[test_aes128_gcm_siv_aft_naive]()

    comptime if HAS_AES_AARCH64:
        suite.test[test_aes128_gcm_siv_aft_aarch64]()

    comptime if HAS_AES_X86:
        suite.test[test_aes128_gcm_siv_aft_x86]()

    comptime if HAS_GPU:
        suite.test[test_aes128_gcm_siv_aft_gpu]()

    suite^.run()
