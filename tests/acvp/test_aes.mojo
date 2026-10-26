from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from max.gpu.host import DeviceContext
from std.reflection import reflect

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import (
    AesFactory,
    AesAarch64Factory,
    AesGpuFactory,
    AesNaiveFactory,
    AesX86Factory,
)
from tests.platform import HAS_AES_AARCH64, HAS_AES_X86, HAS_GPU


# Dedicated to the ECB AFT/MCT vectors only: no iv/aad/tag/test_passed
# fields, unlike the generic AesTestVector used for the other modes.
@fieldwise_init
struct EcbTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


def parse_acvp_aes_ecb_aft(
    python_vectors: PythonObject,
) raises -> List[EcbTestVector]:
    var vectors = List[EcbTestVector]()
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
            pt_hex = String(expected["pt"])

        vectors.append(
            EcbTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex_decode(String(test["key"])),
                pt=hex_decode(pt_hex),
                ct=hex_decode(ct_hex),
            )
        )
    return vectors^


def parse_acvp_aes_ecb_mct(
    python_vectors: PythonObject,
) raises -> List[EcbTestVector]:
    var vectors = List[EcbTestVector]()
    for v in python_vectors:
        var group = v["group"]
        var expected = v["expected"]
        var is_encrypt = String(group["direction"]) == "encrypt"

        var i = 0
        for entry in expected["resultsArray"]:
            vectors.append(
                EcbTestVector(
                    is_encrypt=is_encrypt,
                    count=i,
                    key=hex_decode(String(entry["key"])),
                    pt=hex_decode(String(entry["pt"])),
                    ct=hex_decode(String(entry["ct"])),
                )
            )
            i += 1
    return vectors^


def check_aes_ecb_aft[
    F: AesFactory
](factory: F, vectors: List[EcbTestVector]) raises:
    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var msg = "[{}], count={}".format(reflect[F.Cipher].name(), v.count)

        var cipher = factory.create(to_array[F.KEY_SIZE](v.key))

        var pt = v.pt.copy()
        cipher.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        cipher.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


def check_aes_ecb_mct[
    F: AesFactory
](factory: F, vectors: List[EcbTestVector]) raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var block = v.pt.copy() if v.is_encrypt else v.ct.copy()
        var expected = v.ct.copy() if v.is_encrypt else v.pt.copy()
        var key = to_array[F.KEY_SIZE](v.key)

        var cipher = factory.create(key)
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                cipher.encrypt(block[:])
            else:
                cipher.decrypt(block[:])

        var msg = "[{}], count={}".format(reflect[F.Cipher].name(), v.count)
        assert_equal(block, expected, msg=msg)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def aes_ecb_aft_vectors() raises -> List[EcbTestVector]:
    return parse_acvp_aes_ecb_aft(
        load_python_acvp_vectors("ACVP-AES-ECB", "AFT")
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def aes_ecb_mct_vectors() raises -> List[EcbTestVector]:
    return parse_acvp_aes_ecb_mct(
        load_python_acvp_vectors("ACVP-AES-ECB", "MCT")
    )


def test_aes128_ecb_aft_naive() raises:
    check_aes_ecb_aft(AesNaiveFactory[16](), aes_ecb_aft_vectors())


def test_aes128_ecb_mct_naive() raises:
    check_aes_ecb_mct(AesNaiveFactory[16](), aes_ecb_mct_vectors())


def test_aes192_ecb_aft_naive() raises:
    check_aes_ecb_aft(AesNaiveFactory[24](), aes_ecb_aft_vectors())


def test_aes192_ecb_mct_naive() raises:
    check_aes_ecb_mct(AesNaiveFactory[24](), aes_ecb_mct_vectors())


def test_aes256_ecb_aft_naive() raises:
    check_aes_ecb_aft(AesNaiveFactory[32](), aes_ecb_aft_vectors())


def test_aes256_ecb_mct_naive() raises:
    check_aes_ecb_mct(AesNaiveFactory[32](), aes_ecb_mct_vectors())


def test_aes128_ecb_aft_aarch64() raises:
    check_aes_ecb_aft(AesAarch64Factory[16](), aes_ecb_aft_vectors())


def test_aes128_ecb_mct_aarch64() raises:
    check_aes_ecb_mct(AesAarch64Factory[16](), aes_ecb_mct_vectors())


def test_aes192_ecb_aft_aarch64() raises:
    check_aes_ecb_aft(AesAarch64Factory[24](), aes_ecb_aft_vectors())


def test_aes192_ecb_mct_aarch64() raises:
    check_aes_ecb_mct(AesAarch64Factory[24](), aes_ecb_mct_vectors())


def test_aes256_ecb_aft_aarch64() raises:
    check_aes_ecb_aft(AesAarch64Factory[32](), aes_ecb_aft_vectors())


def test_aes256_ecb_mct_aarch64() raises:
    check_aes_ecb_mct(AesAarch64Factory[32](), aes_ecb_mct_vectors())


def test_aes128_ecb_aft_x86() raises:
    check_aes_ecb_aft(AesX86Factory[16](), aes_ecb_aft_vectors())


def test_aes128_ecb_mct_x86() raises:
    check_aes_ecb_mct(AesX86Factory[16](), aes_ecb_mct_vectors())


def test_aes192_ecb_aft_x86() raises:
    check_aes_ecb_aft(AesX86Factory[24](), aes_ecb_aft_vectors())


def test_aes192_ecb_mct_x86() raises:
    check_aes_ecb_mct(AesX86Factory[24](), aes_ecb_mct_vectors())


def test_aes256_ecb_aft_x86() raises:
    check_aes_ecb_aft(AesX86Factory[32](), aes_ecb_aft_vectors())


def test_aes256_ecb_mct_x86() raises:
    check_aes_ecb_mct(AesX86Factory[32](), aes_ecb_mct_vectors())


def test_aes128_ecb_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ecb_aft(AesGpuFactory[16](ctx), aes_ecb_aft_vectors())


def test_aes128_ecb_mct_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ecb_mct(AesGpuFactory[16](ctx), aes_ecb_mct_vectors())


def test_aes192_ecb_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ecb_aft(AesGpuFactory[24](ctx), aes_ecb_aft_vectors())


def test_aes192_ecb_mct_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ecb_mct(AesGpuFactory[24](ctx), aes_ecb_mct_vectors())


def test_aes256_ecb_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ecb_aft(AesGpuFactory[32](ctx), aes_ecb_aft_vectors())


def test_aes256_ecb_mct_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_ecb_mct(AesGpuFactory[32](ctx), aes_ecb_mct_vectors())


def main() raises:
    var suite = TestSuite()

    suite.test[test_aes128_ecb_aft_naive]()
    suite.test[test_aes128_ecb_mct_naive]()
    suite.test[test_aes192_ecb_aft_naive]()
    suite.test[test_aes192_ecb_mct_naive]()
    suite.test[test_aes256_ecb_aft_naive]()
    suite.test[test_aes256_ecb_mct_naive]()

    comptime if HAS_AES_AARCH64:
        suite.test[test_aes128_ecb_aft_aarch64]()
        suite.test[test_aes128_ecb_mct_aarch64]()
        suite.test[test_aes192_ecb_aft_aarch64]()
        suite.test[test_aes192_ecb_mct_aarch64]()
        suite.test[test_aes256_ecb_aft_aarch64]()
        suite.test[test_aes256_ecb_mct_aarch64]()

    comptime if HAS_AES_X86:
        suite.test[test_aes128_ecb_aft_x86]()
        suite.test[test_aes128_ecb_mct_x86]()
        suite.test[test_aes192_ecb_aft_x86]()
        suite.test[test_aes192_ecb_mct_x86]()
        suite.test[test_aes256_ecb_aft_x86]()
        suite.test[test_aes256_ecb_mct_x86]()

    comptime if HAS_GPU:
        suite.test[test_aes128_ecb_aft_gpu]()
        suite.test[test_aes128_ecb_mct_gpu]()
        suite.test[test_aes192_ecb_aft_gpu]()
        suite.test[test_aes192_ecb_mct_gpu]()
        suite.test[test_aes256_ecb_aft_gpu]()
        suite.test[test_aes256_ecb_mct_gpu]()

    suite^.run()
