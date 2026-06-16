from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.traits import UniversalHashable
from mojo_crypto.universal_hashes.ghash import GHashCpu
from mojo_crypto.universal_hashes.ghash.common import BLOCK_SIZE
from mojo_crypto.universal_hashes.polyval.field_element import FieldElement


def check_ghash_test_vector[
    T: UniversalHashable & Movable & ImplicitlyDestructible,
    poly_init: def(InlineArray[UInt8, BLOCK_SIZE]) capturing[_] -> T,
]() raises:
    comptime assert T.TAG_SIZE == BLOCK_SIZE, "TAG_SIZE must equal BLOCK_SIZE"
    hex = Hex()
    var h = hex.decode[BLOCK_SIZE]("25629347589242761d31f826ba4b757b")
    var x1 = hex.decode[BLOCK_SIZE]("4f4f95668c83dfb6401762bb2d01a262")
    var x2 = hex.decode[BLOCK_SIZE]("d1a24ddd2721d006bbe45f20d3c9f362")

    var poly = poly_init(h)
    poly.update(x1)
    poly.update(x2)

    assert_equal(
        FieldElement(rebind[InlineArray[UInt8, BLOCK_SIZE]](poly^.finalize())),
        FieldElement(
            hex.decode[BLOCK_SIZE]("bd9b3997046731fb96251b91f9c99d7a")
        ),
    )


# Test vectors for GHASH from RFC 8452 Appendix A
# <https://tools.ietf.org/html/rfc8452#appendix-A>
def test_ghash_test_vector() raises:
    @parameter
    def ghash_cpu(h: InlineArray[UInt8, BLOCK_SIZE]) -> GHashCpu:
        return GHashCpu(h)

    check_ghash_test_vector[GHashCpu, ghash_cpu]()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
