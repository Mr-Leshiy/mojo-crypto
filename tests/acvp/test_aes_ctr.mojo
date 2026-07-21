from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.modes import CtrMode

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import run_aes_checks


@fieldwise_init
struct CtrTestVector(Copyable, Movable):
    var is_encrypt: Bool
    var count: Int
    var key: List[UInt8]
    var iv: List[UInt8]
    var pt: List[UInt8]
    var ct: List[UInt8]


def parse_acvp_aes_ctr_aft(
    python_vectors: PythonObject,
) raises -> List[CtrTestVector]:
    var vectors = List[CtrTestVector]()
    hex = Hex()
    for v in python_vectors:
        group = v["group"]
        test = v["test"]
        expected = v["expected"]
        is_encrypt = String(group["direction"]) == "encrypt"

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
                key=hex.decode(String(test["key"])),
                iv=hex.decode(String(test["iv"])),
                pt=hex.decode(String(expected["pt"])),
                ct=hex.decode(String(test["ct"])),
            )
        )
    return vectors^


def check_aes_ctr_aft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CtrTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[CtrMode[{}]], count={}".format(reflect[C]().name(), v.count)

        var key = to_inline_array[KeySize](v.key)
        var iv = to_inline_array[C.BLOCK_SIZE](v.iv)

        if v.is_encrypt:
            var pt = v.pt.copy()
            var ctr = CtrMode[C](cipher_init(key), iv)
            ctr.encrypt(pt[:])
            assert_equal(pt, v.ct, msg=msg)
        else:
            var ct = v.ct.copy()
            var ctr = CtrMode[C](cipher_init(key), iv)
            ctr.decrypt(ct[:])
            assert_equal(ct, v.pt, msg=msg)


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ACVP-AES-CTR-1.0
# AES-CTR only defines AFT groups (no MCT).
def test_aes_ctr_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/acvp/data/ACVP-AES-CTR-1.0", "AFT"
    )
    run_aes_checks[CtrTestVector, check_aes_ctr_aft](
        parse_acvp_aes_ctr_aft(raw)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
