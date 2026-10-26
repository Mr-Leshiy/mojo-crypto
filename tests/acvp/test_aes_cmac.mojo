from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from max.gpu.host import DeviceContext
from std.reflection import reflect

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.macs import Cmac

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
struct CmacTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var pt: List[UInt8]
    # Authentication tag, possibly truncated (macLen varies per group).
    var tag: List[UInt8]
    # For "ver" (verify) vectors: whether the given MAC is expected to match.
    var test_passed: Bool


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/CMAC-AES-1.0
# CMAC only defines AFT groups (no MCT).
def parse_acvp_aes_cmac_aft(
    python_vectors: PythonObject,
) raises -> List[CmacTestVector]:
    var vectors = List[CmacTestVector]()
    for v in python_vectors:
        var group = v["group"]
        var test = v["test"]
        var expected = v["expected"]

        # CMAC uses "gen"/"ver" instead of "encrypt"/"decrypt" for the same
        # produce-vs-check duality: "gen" computes the canonical MAC (like
        # encrypt), "ver" checks a possibly-wrong candidate (like GCM
        # decrypt).
        var is_encrypt = String(group["direction"]) == "gen"

        # The MAC may be truncated below the full block (macLen 64..128
        # bits); tag_hex is left at whatever length the JSON already gives,
        # so callers derive the truncation from len(tag) rather than a
        # separate field.
        var tag_hex: String
        if is_encrypt:
            tag_hex = String(expected["mac"])
        else:
            tag_hex = String(test["mac"])

        vectors.append(
            CmacTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex_decode(String(test["key"])),
                pt=hex_decode(String(test["message"])),
                tag=hex_decode(tag_hex),
                test_passed=expected.get("testPassed", True).__bool__(),
            )
        )
    return vectors^


def check_aes_cmac_aft[
    F: AesFactory
](factory: F, vectors: List[CmacTestVector]) raises:
    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var msg = "[Cmac[{}]], count={}".format(
            reflect[F.Cipher].name(), v.count
        )

        var cmac = Cmac[F.Cipher](factory.create(to_array[F.KEY_SIZE](v.key)))
        cmac.update(v.pt[:])
        var full_tag = cmac^.finalize()

        # ACVP CMAC vectors may specify a MAC truncated below the full block
        # (64..128 bits); v.tag is already decoded at that length, so only
        # compare that many leading bytes of our computed tag.
        var actual_mac = List[UInt8](capacity=len(v.tag))
        for i in range(len(v.tag)):
            actual_mac.append(full_tag[i])

        if v.is_encrypt:
            assert_equal(actual_mac, v.tag, msg=msg)
        else:
            assert_equal(actual_mac == v.tag, v.test_passed, msg=msg)


def test_aes128_cmac_aft_naive() raises:
    check_aes_cmac_aft(
        AesNaiveFactory[16](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes192_cmac_aft_naive() raises:
    check_aes_cmac_aft(
        AesNaiveFactory[24](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes256_cmac_aft_naive() raises:
    check_aes_cmac_aft(
        AesNaiveFactory[32](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes128_cmac_aft_aarch64() raises:
    check_aes_cmac_aft(
        AesAarch64Factory[16](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes192_cmac_aft_aarch64() raises:
    check_aes_cmac_aft(
        AesAarch64Factory[24](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes256_cmac_aft_aarch64() raises:
    check_aes_cmac_aft(
        AesAarch64Factory[32](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes128_cmac_aft_x86() raises:
    check_aes_cmac_aft(
        AesX86Factory[16](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes192_cmac_aft_x86() raises:
    check_aes_cmac_aft(
        AesX86Factory[24](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes256_cmac_aft_x86() raises:
    check_aes_cmac_aft(
        AesX86Factory[32](),
        parse_acvp_aes_cmac_aft(load_python_acvp_vectors("CMAC-AES", "AFT")),
    )


def test_aes128_cmac_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cmac_aft(
            AesGpuFactory[16](ctx),
            parse_acvp_aes_cmac_aft(
                load_python_acvp_vectors("CMAC-AES", "AFT")
            ),
        )


def test_aes192_cmac_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cmac_aft(
            AesGpuFactory[24](ctx),
            parse_acvp_aes_cmac_aft(
                load_python_acvp_vectors("CMAC-AES", "AFT")
            ),
        )


def test_aes256_cmac_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cmac_aft(
            AesGpuFactory[32](ctx),
            parse_acvp_aes_cmac_aft(
                load_python_acvp_vectors("CMAC-AES", "AFT")
            ),
        )


def main() raises:
    var suite = TestSuite()

    suite.test[test_aes128_cmac_aft_naive]()
    suite.test[test_aes192_cmac_aft_naive]()
    suite.test[test_aes256_cmac_aft_naive]()

    comptime if HAS_AES_AARCH64:
        suite.test[test_aes128_cmac_aft_aarch64]()
        suite.test[test_aes192_cmac_aft_aarch64]()
        suite.test[test_aes256_cmac_aft_aarch64]()

    comptime if HAS_AES_X86:
        suite.test[test_aes128_cmac_aft_x86]()
        suite.test[test_aes192_cmac_aft_x86]()
        suite.test[test_aes256_cmac_aft_x86]()

    comptime if HAS_GPU:
        suite.test[test_aes128_cmac_aft_gpu]()
        suite.test[test_aes192_cmac_aft_gpu]()
        suite.test[test_aes256_cmac_aft_gpu]()

    suite^.run()
