from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect
from max.gpu.host import DeviceContext

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.factories.aes import (
    AesAarch64Factory,
    AesNaiveFactory,
    AesX86Factory,
)
from tests.block_ciphers.factories.cbc import (
    CbcFactory,
    CbcModeFactory,
    GpuCbcModeFactory,
)
from tests.platform import HAS_GPU, register_platform_tests


@fieldwise_init
struct CbcTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def parse_acvp_aes_cbc_aft(
    python_vectors: PythonObject,
) raises -> List[CbcTestVector]:
    var vectors = List[CbcTestVector]()
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
            CbcTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex_decode(String(test["key"])),
                iv=hex_decode(String(test["iv"])),
                pt=hex_decode(pt_hex),
                ct=hex_decode(ct_hex),
            )
        )
    return vectors^


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def parse_acvp_aes_cbc_mct(
    python_vectors: PythonObject,
) raises -> List[CbcTestVector]:
    var vectors = List[CbcTestVector]()
    for v in python_vectors:
        var group = v["group"]
        var expected = v["expected"]
        var is_encrypt = String(group["direction"]) == "encrypt"

        var i = 0
        for entry in expected["resultsArray"]:
            vectors.append(
                CbcTestVector(
                    is_encrypt=is_encrypt,
                    count=i,
                    key=hex_decode(String(entry["key"])),
                    iv=hex_decode(String(entry["iv"])),
                    pt=hex_decode(String(entry["pt"])),
                    ct=hex_decode(String(entry["ct"])),
                )
            )
            i += 1
    return vectors^


def check_aes_cbc_aft[
    F: CbcFactory
](factory: F, vectors: List[CbcTestVector]) raises:
    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var msg = "[{}], count={}".format(reflect[F.Mode].name(), v.count)

        var key = to_array[F.KEY_SIZE](v.key)
        var iv = to_array[F.BLOCK_SIZE](v.iv)
        var pt = v.pt.copy()

        var cbc_enc = factory.create(key, iv.copy())
        cbc_enc.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        var cbc_dec = factory.create(key, iv^)
        cbc_dec.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


def check_aes_cbc_mct[
    F: CbcFactory
](factory: F, vectors: List[CbcTestVector]) raises:
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in vectors:
        if len(v.key) != F.KEY_SIZE:
            continue

        var msg = "[{}], count={}".format(reflect[F.Mode].name(), v.count)

        var key = to_array[F.KEY_SIZE](v.key)
        var iv = to_array[F.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var block = v.pt.copy()
            var next_block = v.iv.copy()
            var cbc = factory.create(key, iv^)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.encrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.ct, msg=msg)
        else:
            var block = v.ct.copy()
            var next_block = v.iv.copy()
            var cbc = factory.create(key, iv^)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.decrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.pt, msg=msg)


def test_aes128_cbc_aft_naive() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesNaiveFactory[16]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes128_cbc_mct_naive() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesNaiveFactory[16]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes192_cbc_aft_naive() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesNaiveFactory[24]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes192_cbc_mct_naive() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesNaiveFactory[24]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes256_cbc_aft_naive() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesNaiveFactory[32]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes256_cbc_mct_naive() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesNaiveFactory[32]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes128_cbc_aft_aarch64() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesAarch64Factory[16]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes128_cbc_mct_aarch64() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesAarch64Factory[16]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes192_cbc_aft_aarch64() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesAarch64Factory[24]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes192_cbc_mct_aarch64() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesAarch64Factory[24]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes256_cbc_aft_aarch64() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesAarch64Factory[32]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes256_cbc_mct_aarch64() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesAarch64Factory[32]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes128_cbc_aft_x86() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesX86Factory[16]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes128_cbc_mct_x86() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesX86Factory[16]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes192_cbc_aft_x86() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesX86Factory[24]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes192_cbc_mct_x86() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesX86Factory[24]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes256_cbc_aft_x86() raises:
    check_aes_cbc_aft(
        CbcModeFactory(AesX86Factory[32]()),
        parse_acvp_aes_cbc_aft(load_python_acvp_vectors("ACVP-AES-CBC", "AFT")),
    )


def test_aes256_cbc_mct_x86() raises:
    check_aes_cbc_mct(
        CbcModeFactory(AesX86Factory[32]()),
        parse_acvp_aes_cbc_mct(load_python_acvp_vectors("ACVP-AES-CBC", "MCT")),
    )


def test_aes128_cbc_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cbc_aft(
            GpuCbcModeFactory[16](ctx),
            parse_acvp_aes_cbc_aft(
                load_python_acvp_vectors("ACVP-AES-CBC", "AFT")
            ),
        )


def test_aes128_cbc_mct_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cbc_mct(
            GpuCbcModeFactory[16](ctx),
            parse_acvp_aes_cbc_mct(
                load_python_acvp_vectors("ACVP-AES-CBC", "MCT")
            ),
        )


def test_aes192_cbc_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cbc_aft(
            GpuCbcModeFactory[24](ctx),
            parse_acvp_aes_cbc_aft(
                load_python_acvp_vectors("ACVP-AES-CBC", "AFT")
            ),
        )


def test_aes192_cbc_mct_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cbc_mct(
            GpuCbcModeFactory[24](ctx),
            parse_acvp_aes_cbc_mct(
                load_python_acvp_vectors("ACVP-AES-CBC", "MCT")
            ),
        )


def test_aes256_cbc_aft_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cbc_aft(
            GpuCbcModeFactory[32](ctx),
            parse_acvp_aes_cbc_aft(
                load_python_acvp_vectors("ACVP-AES-CBC", "AFT")
            ),
        )


def test_aes256_cbc_mct_gpu() raises:
    with DeviceContext() as ctx:
        check_aes_cbc_mct(
            GpuCbcModeFactory[32](ctx),
            parse_acvp_aes_cbc_mct(
                load_python_acvp_vectors("ACVP-AES-CBC", "MCT")
            ),
        )


def main() raises:
    var suite = TestSuite()
    register_platform_tests[__functions_in_module()](suite)
    comptime if HAS_GPU:
        suite.skip[test_aes128_cbc_aft_gpu]()
        suite.skip[test_aes128_cbc_mct_gpu]()
        suite.skip[test_aes192_cbc_aft_gpu]()
        suite.skip[test_aes192_cbc_mct_gpu]()
        suite.skip[test_aes256_cbc_aft_gpu]()
        suite.skip[test_aes256_cbc_mct_gpu]()
        # Skipped until https://github.com/modular/modular/issues/7368 is
        # fixed. The GPU tests are only registered when `HAS_GPU` is set, and
        # skipping an unregistered test is an error.
    suite^.run()
