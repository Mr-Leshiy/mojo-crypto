from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.polyval.field_element import FieldElement
from mojo_crypto.universal_hashes.polyval._common import BLOCK_SIZE


# Test vectors from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element.rs
def test_fe_add() raises:
    hex = Hex()
    a = FieldElement(hex.decode[BLOCK_SIZE]("66e94bd4ef8a2c3b884cfa59ca342b2e"))
    b = FieldElement(hex.decode[BLOCK_SIZE]("ff000000000000000000000000000000"))
    expected = FieldElement(
        hex.decode[BLOCK_SIZE]("99e94bd4ef8a2c3b884cfa59ca342b2e")
    )

    assert_equal(a + b, expected)
    assert_equal(b + a, expected)

    zero = FieldElement(
        hex.decode[BLOCK_SIZE]("00000000000000000000000000000000")
    )

    assert_equal(a + zero, a)
    assert_equal(zero + a, a)

    assert_equal(a + a, zero)


# Test vectors from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element.rs
def test_fe_mul() raises:
    hex = Hex()

    a = FieldElement(hex.decode[BLOCK_SIZE]("66e94bd4ef8a2c3b884cfa59ca342b2e"))
    b = FieldElement(hex.decode[BLOCK_SIZE]("ff000000000000000000000000000000"))
    expected = FieldElement(
        hex.decode[BLOCK_SIZE]("ebe563401e7e91ea3ad6426b8140c394")
    )

    assert_equal(a * b, expected)
    assert_equal(b * a, expected)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
