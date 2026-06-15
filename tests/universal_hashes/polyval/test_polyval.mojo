from std.memory import memcpy
from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.polyval.field_element import FieldElement
from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE


# Test vectors from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element.rs
def test_fe_add() raises:
    hex = Hex()
    var a = FieldElement(
        hex.decode[BLOCK_SIZE]("66e94bd4ef8a2c3b884cfa59ca342b2e")
    )
    var b = FieldElement(
        hex.decode[BLOCK_SIZE]("ff000000000000000000000000000000")
    )
    var expected = FieldElement(
        hex.decode[BLOCK_SIZE]("99e94bd4ef8a2c3b884cfa59ca342b2e")
    )

    assert_equal(a + b, expected)
    assert_equal(b + a, expected)

    var zero = FieldElement(
        hex.decode[BLOCK_SIZE]("00000000000000000000000000000000")
    )

    assert_equal(a + zero, a)
    assert_equal(zero + a, a)

    assert_equal(a + a, zero)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
