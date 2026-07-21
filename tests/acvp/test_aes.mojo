from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import run_aes_checks


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
            pt_hex = String(expected["pt"])

        vectors.append(
            EcbTestVector(
                is_encrypt=is_encrypt,
                count=Int(py=test["tcId"]),
                key=hex.decode(String(test["key"])),
                pt=hex.decode(pt_hex),
                ct=hex.decode(ct_hex),
            )
        )
    return vectors^


def parse_acvp_aes_ecb_mct(
    python_vectors: PythonObject,
) raises -> List[EcbTestVector]:
    var vectors = List[EcbTestVector]()
    hex = Hex()
    for v in python_vectors:
        group = v["group"]
        expected = v["expected"]
        is_encrypt = String(group["direction"]) == "encrypt"

        var i = 0
        for entry in expected["resultsArray"]:
            vectors.append(
                EcbTestVector(
                    is_encrypt=is_encrypt,
                    count=i,
                    key=hex.decode(String(entry["key"])),
                    pt=hex.decode(String(entry["pt"])),
                    ct=hex.decode(String(entry["ct"])),
                )
            )
            i += 1
    return vectors^


def check_aes_ecb_aft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[EcbTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[{}], count={}".format(reflect[C]().name(), v.count)

        var cipher = cipher_init(to_inline_array[KeySize](v.key))

        var pt = v.pt.copy()
        cipher.encrypt(pt[:])
        assert_equal(pt, v.ct, msg=msg)

        var ct = v.ct.copy()
        cipher.decrypt(ct[:])
        assert_equal(ct, v.pt, msg=msg)


def check_aes_ecb_mct[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[EcbTestVector]) raises:
    # Number of inner iterations per MCT outer loop, as specified in AESAVS section 6.4.1:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
    comptime MCT_INNER_ITERATIONS: Int = 1000

    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var block = v.pt.copy() if v.is_encrypt else v.ct.copy()
        var expected = v.ct.copy() if v.is_encrypt else v.pt.copy()
        var key = to_inline_array[KeySize](v.key)

        var cipher = cipher_init(key)
        for _ in range(MCT_INNER_ITERATIONS):
            if v.is_encrypt:
                cipher.encrypt(block[:])
            else:
                cipher.decrypt(block[:])

        var msg = "[{}], count={}".format(reflect[C]().name(), v.count)
        assert_equal(block, expected, msg=msg)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def test_aes_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-ECB-1.0", "AFT"
    )
    run_aes_checks[EcbTestVector, check_aes_ecb_aft](
        parse_acvp_aes_ecb_aft(raw)
    )


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-ECB-1.0
def test_aes_mct() raises:
    var raw = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/ACVP-AES-ECB-1.0", "MCT"
    )
    run_aes_checks[EcbTestVector, check_aes_ecb_mct](
        parse_acvp_aes_ecb_mct(raw)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
