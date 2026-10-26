from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from max.gpu.host import DeviceContext
from std.reflection import reflect

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.block_ciphers.modes import CtrMode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import (
    AesFactory,
    AesAarch64Factory,
    AesGpuFactory,
    AesNaiveFactory,
    AesX86Factory,
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
    F: AesFactory
](factory: F, vectors: List[CtrTestVector]) raises:
    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var msg = "[CtrMode[{}]], count={}".format(
            reflect[F.Cipher].name(), v.count
        )

        var key = to_array[F.KEY_SIZE](v.key)
        var iv = to_array[F.Cipher.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var pt = v.pt.copy()
            var ctr = CtrMode[F.Cipher](factory.create(key), iv^)
            ctr.encrypt(pt[:])
            assert_equal(pt, v.ct, msg=msg)
        else:
            var ct = v.ct.copy()
            var ctr = CtrMode[F.Cipher](factory.create(key), iv^)
            ctr.decrypt(ct[:])
            assert_equal(ct, v.pt, msg=msg)


def test_aes128_ctr_aft_naive() raises:
    check_aes_ctr_aft(
        AesNaiveFactory[16](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes192_ctr_aft_naive() raises:
    check_aes_ctr_aft(
        AesNaiveFactory[24](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes256_ctr_aft_naive() raises:
    check_aes_ctr_aft(
        AesNaiveFactory[32](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes128_ctr_aft_aarch64() raises:
    check_aes_ctr_aft(
        AesAarch64Factory[16](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes192_ctr_aft_aarch64() raises:
    check_aes_ctr_aft(
        AesAarch64Factory[24](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes256_ctr_aft_aarch64() raises:
    check_aes_ctr_aft(
        AesAarch64Factory[32](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes128_ctr_aft_x86() raises:
    check_aes_ctr_aft(
        AesX86Factory[16](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes192_ctr_aft_x86() raises:
    check_aes_ctr_aft(
        AesX86Factory[24](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes256_ctr_aft_x86() raises:
    check_aes_ctr_aft(
        AesX86Factory[32](),
        parse_acvp_aes_ctr_aft(load_python_acvp_vectors("ACVP-AES-CTR", "AFT")),
    )


def test_aes128_ctr_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ctr_aft(
            AesGpuFactory[16](ctx),
            parse_acvp_aes_ctr_aft(
                load_python_acvp_vectors("ACVP-AES-CTR", "AFT")
            ),
        )


def test_aes192_ctr_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ctr_aft(
            AesGpuFactory[24](ctx),
            parse_acvp_aes_ctr_aft(
                load_python_acvp_vectors("ACVP-AES-CTR", "AFT")
            ),
        )


def test_aes256_ctr_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ctr_aft(
            AesGpuFactory[32](ctx),
            parse_acvp_aes_ctr_aft(
                load_python_acvp_vectors("ACVP-AES-CTR", "AFT")
            ),
        )


def main() raises:
    var suite = TestSuite()
    register_platform_tests[__functions_in_module()](suite)
    suite^.run()
