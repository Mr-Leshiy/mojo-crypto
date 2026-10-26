from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.factories.aes import (
    AesAarch64Factory,
    AesNaiveFactory,
    AesX86Factory,
)
from tests.block_ciphers.factories.ctr import (
    CtrFactory,
    CtrModeFactory,
)
from tests.platform import register_platform_tests


@fieldwise_init
struct CtrTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CTR-1.0
# AES-CTR only defines AFT groups (no MCT).
def parse_acvp_aes_ctr_aft(
    python_vectors: PythonObject,
) raises -> List[CtrTestVector]:
    var vectors = List[CtrTestVector]()
    for v in python_vectors:
        var group = v["group"]
        var test = v["test"]
        var expected = v["expected"]
        var is_encrypt = String(group["direction"]) == "encrypt"

        # CTR encryption vectors carry the IV in expectedResults rather than
        # the prompt; skip them and rely on the decryption vectors (same
        # keystream logic, IV available in the prompt).
        if is_encrypt:
            continue

        # Skip non-byte-aligned payloads (payloadLen field is in bits).
        if Int(py=test["payloadLen"]) % 8 != 0:
            continue

        vectors.append(
            CtrTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex_decode(String(test["key"])),
                iv=hex_decode(String(test["iv"])),
                pt=hex_decode(String(expected["pt"])),
                ct=hex_decode(String(test["ct"])),
            )
        )
    return vectors^


def check_aes_ctr_aft[
    F: CtrFactory
](factory: F, vectors: List[CtrTestVector]) raises:
    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var msg = "[{}], count={}".format(reflect[F.Mode].name(), v.count)

        var key = to_array[F.KEY_SIZE](v.key)
        var iv = to_array[F.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var pt = v.pt.copy()
            var ctr = factory.create(key, iv^)
            ctr.encrypt(pt[:])
            assert_equal(pt, v.ct, msg=msg)
        else:
            var ct = v.ct.copy()
            var ctr = factory.create(key, iv^)
            ctr.decrypt(ct[:])
            assert_equal(ct, v.pt, msg=msg)


def test_aes128_ctr_aft_naive() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesNaiveFactory[16]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes192_ctr_aft_naive() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesNaiveFactory[24]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes256_ctr_aft_naive() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesNaiveFactory[32]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes128_ctr_aft_aarch64() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesAarch64Factory[16]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes192_ctr_aft_aarch64() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesAarch64Factory[24]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes256_ctr_aft_aarch64() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesAarch64Factory[32]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes128_ctr_aft_x86() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesX86Factory[16]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes192_ctr_aft_x86() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesX86Factory[24]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes256_ctr_aft_x86() raises:
    check_aes_ctr_aft(
        CtrModeFactory(AesX86Factory[32]()),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


# The GPU-backed CTR tests are disabled until
# https://github.com/modular/modular/issues/7368 is fixed. Every function in
# this module is compiled even when it is not registered, so they cannot just
# be left unregistered. Restore them with `GpuCtrModeFactory`.


def main() raises:
    var suite = TestSuite()
    register_platform_tests[__functions_in_module()](suite)
    suite^.run()
