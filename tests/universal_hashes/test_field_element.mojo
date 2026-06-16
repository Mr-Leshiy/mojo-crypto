from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.polyval.field_element import FieldElement
from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE


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


# Test vector given in RFC 8452 Appendix A.
#
# NOTE: the vector in the RFC actually contains a typo which has been reported (and accepted)
# as RFC errata, so we use the vector from the errata instead:
#
# <https://www.rfc-editor.org/errata_search.php?rfc=8452>
def test_fe_mulx_rfc8452_vector() raises:
    hex = Hex()
    input = FieldElement(
        hex.decode[BLOCK_SIZE]("9c98c04df9387ded828175a92ba652d8")
    )
    expected_output = FieldElement(
        hex.decode[BLOCK_SIZE]("3931819bf271fada0503eb52574ca572")
    )
    assert_equal(expected_output, input.mulx())


# Test vectors from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element/mulx.rs
def test_fe_mulx() raises:
    hex = Hex()

    MULX_TEST_VECTORS = [
        FieldElement(
            hex.decode[BLOCK_SIZE]("02000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("04000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("08000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("10000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("20000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("40000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("80000000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00010000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00020000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00040000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00080000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00100000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00200000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00400000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00800000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000100000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000200000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000400000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000800000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00001000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00002000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00004000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00008000000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000001000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000002000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000004000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000008000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000010000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000020000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000040000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000080000000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000010000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000020000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000040000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000080000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000100000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000200000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000400000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000800000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000100000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000200000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000400000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000800000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000001000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000002000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000004000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000008000000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000001000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000002000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000004000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000008000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000010000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000020000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000040000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000080000000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000010000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000020000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000040000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000080000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000100000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000200000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000400000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000800000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000100000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000200000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000400000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000800000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000001000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000002000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000004000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000008000000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000001000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000002000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000004000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000008000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000010000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000020000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000040000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000080000000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000010000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000020000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000040000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000080000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000100000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000200000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000400000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000800000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000100000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000200000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000400000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000800000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000001000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000002000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000004000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000008000000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000001000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000002000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000004000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000008000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000010000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000020000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000040000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000080000000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000010000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000020000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000040000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000080000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000100000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000200000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000400000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000800000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000100")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000200")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000400")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000800")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000001000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000002000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000004000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000008000")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000001")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000002")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000004")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000008")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000010")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000020")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000040")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("00000000000000000000000000000080")
        ),
        FieldElement(
            hex.decode[BLOCK_SIZE]("010000000000000000000000000000c2")
        ),
    ]
    r = FieldElement(hex.decode[BLOCK_SIZE]("01000000000000000000000000000000"))

    for vec in MULX_TEST_VECTORS:
        r = r.mulx()
        assert_equal(vec, r)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
