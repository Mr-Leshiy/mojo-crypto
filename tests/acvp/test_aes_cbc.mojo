from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.modes import CbcMode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import run_aes_checks


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
        group = v["group"]
        expected = v["expected"]
        is_encrypt = String(group["direction"]) == "encrypt"

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
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CbcTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[CbcMode[{}]], count={}".format(reflect[C]().name(), v.count)

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)
        var pt = v.pt.copy()

        var cbc_enc = CbcMode[C](cipher_init(key), iv)
        cbc_enc.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        var cbc_dec = CbcMode[C](cipher_init(key), iv)
        cbc_dec.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


def check_aes_cbc_mct[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CbcTestVector]) raises:
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[CbcMode[{}]], count={}".format(reflect[C]().name(), v.count)

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var block = v.pt.copy()
            var next_block = v.iv.copy()
            var cbc = CbcMode[C](cipher_init(key), iv)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.encrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.ct, msg=msg)
        else:
            var block = v.ct.copy()
            var next_block = v.iv.copy()
            var cbc = CbcMode[C](cipher_init(key), iv)
            for _ in range(MCT_INNER_ITERATIONS):
                cbc.decrypt(block[:])
                var tmp = block^
                block = next_block^
                next_block = tmp^
            assert_equal(next_block, v.pt, msg=msg)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/ACVP-AES-CBC-1.0", "AFT"
    )
    run_aes_checks[CbcTestVector, check_aes_cbc_aft](
        parse_acvp_aes_cbc_aft(raw)
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CBC-1.0
def test_aes_cbc_mct() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/ACVP-AES-CBC-1.0", "MCT"
    )
    run_aes_checks[CbcTestVector, check_aes_cbc_mct](
        parse_acvp_aes_cbc_mct(raw)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
