from std.sys import has_accelerator
from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect
from warp import Runtime

from mojo_crypto.utils import to_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.block_ciphers.modes import CbcMode, GpuCbcMode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import (
    run_aes_checks,
    run_gpu_aes_checks,
    BlockCipherEngine,
    AsyncBlockCipherEngine,
)


@fieldwise_init
struct CbcTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


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
    C: BlockCipherEngine,
    KeySize: Int,
    //,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CbcTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[CbcMode[{}]], count={}".format(reflect[C].name(), v.count)

        var key = to_array[KeySize](v.key)
        var iv = to_array[C.BLOCK_SIZE](v.iv)
        var pt = v.pt.copy()

        var cbc_enc = CbcMode[C](cipher_init(key), iv.copy())
        cbc_enc.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        var cbc_dec = CbcMode[C](cipher_init(key), iv^)
        cbc_dec.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


def check_aes_cbc_mct[
    C: BlockCipherEngine,
    KeySize: Int,
    //,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CbcTestVector]) raises:
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[CbcMode[{}]], count={}".format(reflect[C].name(), v.count)

        var key = to_array[KeySize](v.key)
        var iv = to_array[C.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var block = v.pt.copy()
            var next_block = v.iv.copy()
            var cbc = CbcMode[C](cipher_init(key), iv^)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.encrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.ct, msg=msg)
        else:
            var block = v.ct.copy()
            var next_block = v.iv.copy()
            var cbc = CbcMode[C](cipher_init(key), iv^)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.decrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.pt, msg=msg)


def check_aes_cbc_aft_async[
    C: AsyncBlockCipherEngine,
    KeySize: Int,
    //,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
](mut runtime: Runtime, vectors: List[CbcTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[GpuCbcMode[{}]], count={}".format(
            reflect[C].name(), v.count
        )

        var key = to_array[KeySize](v.key)
        var iv = to_array[C.BLOCK_SIZE](v.iv)
        var pt = v.pt.copy()

        var cbc_enc = GpuCbcMode[C](cipher_init(key), iv.copy())
        runtime.block_on(cbc_enc.encrypt(runtime.context(), pt[:]))
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        var cbc_dec = GpuCbcMode[C](cipher_init(key), iv^)
        runtime.block_on(cbc_dec.decrypt(runtime.context(), ct[:]))
        assert_equal(ct, v.pt, msg=msg)


def check_aes_cbc_mct_async[
    C: AsyncBlockCipherEngine,
    KeySize: Int,
    //,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
](mut runtime: Runtime, vectors: List[CbcTestVector]) raises:
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[GpuCbcMode[{}]], count={}".format(
            reflect[C].name(), v.count
        )

        var key = to_array[KeySize](v.key)
        var iv = to_array[C.BLOCK_SIZE](v.iv)

        var block = v.pt.copy() if v.is_encrypt else v.ct.copy()
        var expected = v.ct.copy() if v.is_encrypt else v.pt.copy()
        var next_block = v.iv.copy()
        var cbc = GpuCbcMode[C](cipher_init(key), iv^)
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                runtime.block_on(cbc.encrypt(runtime.context(), block[:]))
            else:
                runtime.block_on(cbc.decrypt(runtime.context(), block[:]))
            var tmp = block^
            block = next_block^
            next_block = tmp^
        assert_equal(next_block, expected, msg=msg)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_aft() raises:
    var raw = load_python_acvp_vectors("ACVP-AES-CBC", "AFT")
    run_aes_checks[List[CbcTestVector], check_aes_cbc_aft](
        parse_acvp_aes_cbc_aft(raw)
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_mct() raises:
    var raw = load_python_acvp_vectors("ACVP-AES-CBC", "MCT")
    run_aes_checks[List[CbcTestVector], check_aes_cbc_mct](
        parse_acvp_aes_cbc_mct(raw)
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_aft_gpu() raises:
    var raw = load_python_acvp_vectors("ACVP-AES-CBC", "AFT")
    run_gpu_aes_checks[List[CbcTestVector], check_aes_cbc_aft_async](
        parse_acvp_aes_cbc_aft(raw)
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_mct_gpu() raises:
    var raw = load_python_acvp_vectors("ACVP-AES-CBC", "MCT")
    run_gpu_aes_checks[List[CbcTestVector], check_aes_cbc_mct_async](
        parse_acvp_aes_cbc_mct(raw)
    )


def main() raises:
    var suite = TestSuite.discover_tests[__functions_in_module()]()
    comptime if not has_accelerator():
        suite.skip[test_aes_cbc_aft_gpu]()
        suite.skip[test_aes_cbc_mct_gpu]()
    else:
        # TODO: skipped due to https://github.com/modular/modular/issues/7368,
        # remove this branch once fixed.
        suite.skip[test_aes_cbc_aft_gpu]()
        suite.skip[test_aes_cbc_mct_gpu]()
    suite^.run()
