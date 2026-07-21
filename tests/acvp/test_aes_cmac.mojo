from std.testing import assert_equal, TestSuite
from std.python import PythonObject
from std.reflection import reflect

from mojo_crypto.utils import to_inline_array
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.macs import Cmac

from tests.acvp.utils import load_python_acvp_vectors
from tests.block_ciphers.utils import run_aes_checks


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


def parse_acvp_aes_cmac_aft(
    python_vectors: PythonObject,
) raises -> List[CmacTestVector]:
    var vectors = List[CmacTestVector]()
    hex = Hex()
    for v in python_vectors:
        group = v["group"]
        test = v["test"]
        expected = v["expected"]

        # CMAC uses "gen"/"ver" instead of "encrypt"/"decrypt" for the same
        # produce-vs-check duality: "gen" computes the canonical MAC (like
        # encrypt), "ver" checks a possibly-wrong candidate (like GCM
        # decrypt).
        is_encrypt = String(group["direction"]) == "gen"

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
                key=hex.decode(String(test["key"])),
                pt=hex.decode(String(test["message"])),
                tag=hex.decode(tag_hex),
                test_passed=expected.get("testPassed", True).__bool__(),
            )
        )
    return vectors^


def check_aes_cmac_aft[
    C: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
](vectors: List[CmacTestVector]) raises:
    for v in vectors:
        if len(v.key) != KeySize:
            continue

        var msg = "[Cmac[{}]], count={}".format(reflect[C]().name(), v.count)

        var cmac = Cmac[C](cipher_init(to_inline_array[KeySize](v.key)))
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


# https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/CMAC-AES-1.0
# CMAC only defines AFT groups (no MCT).
def test_aes_cmac_aft() raises:
    var raw = load_python_acvp_vectors(
        "tests/block_ciphers/aes/acvp/CMAC-AES-1.0", "AFT"
    )
    run_aes_checks[CmacTestVector, check_aes_cmac_aft](
        parse_acvp_aes_cmac_aft(raw)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
