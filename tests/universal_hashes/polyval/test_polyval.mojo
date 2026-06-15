from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.polyval.cpu import PolyvalCpu
from mojo_crypto.universal_hashes.polyval.field_element import FieldElement
from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE


# Test vectors from RFC 8452 Appendix A.
# <https://www.rfc-editor.org/rfc/rfc8452#appendix-A>
def test_polyval_test_vector() raises:
    hex = Hex()
    var h = hex.decode[BLOCK_SIZE]("25629347589242761d31f826ba4b757b")
    var x1 = hex.decode[BLOCK_SIZE]("4f4f95668c83dfb6401762bb2d01a262")
    var x2 = hex.decode[BLOCK_SIZE]("d1a24ddd2721d006bbe45f20d3c9f362")

    var poly = PolyvalCpu(h)
    poly.update(
        Span[UInt8, origin_of(x1)](ptr=x1.unsafe_ptr(), length=BLOCK_SIZE)
    )
    poly.update(
        Span[UInt8, origin_of(x2)](ptr=x2.unsafe_ptr(), length=BLOCK_SIZE)
    )

    assert_equal(
        FieldElement(poly^.finalize()),
        FieldElement(
            hex.decode[BLOCK_SIZE]("f7a3b47b846119fae5b7866cf5e5b77e")
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
