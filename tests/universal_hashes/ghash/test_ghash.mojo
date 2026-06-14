from std.memory import memcpy
from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import HexCpu
from mojo_crypto.universal_hashes.ghash.common import FieldElement, BLOCK_SIZE


def _from_hex(s: String) raises -> InlineArray[UInt8, BLOCK_SIZE]:
    var bytes = HexCpu().decode(s)
    if len(bytes) != BLOCK_SIZE:
        raise Error(
            "hex string must decode to {} bytes, got {}".format(
                BLOCK_SIZE, len(bytes)
            )
        )
    var result = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
    memcpy(dest=result.unsafe_ptr(), src=bytes.unsafe_ptr(), count=BLOCK_SIZE)
    return result^


# Test vectors from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element.rs
def test_fe_add() raises:
    var a = FieldElement(_from_hex("66e94bd4ef8a2c3b884cfa59ca342b2e"))
    var b = FieldElement(_from_hex("ff000000000000000000000000000000"))
    var expected = FieldElement(_from_hex("99e94bd4ef8a2c3b884cfa59ca342b2e"))

    assert_equal(a + b, expected)
    assert_equal(b + a, expected)

    var zero = FieldElement(_from_hex("00000000000000000000000000000000"))

    assert_equal(a + zero, a)
    assert_equal(zero + a, a)

    assert_equal(a + a, zero)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
