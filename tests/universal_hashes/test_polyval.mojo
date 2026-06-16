from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.traits import UniversalHashable
from mojo_crypto.universal_hashes.polyval import PolyvalCpu
from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE


def check_polyval_test_vector[
    T: UniversalHashable & Movable & ImplicitlyDestructible,
    poly_init: def(InlineArray[UInt8, BLOCK_SIZE]) capturing[_] -> T,
]() raises:
    hex = Hex()
    var h = hex.decode[BLOCK_SIZE]("25629347589242761d31f826ba4b757b")
    var x1 = hex.decode[BLOCK_SIZE]("4f4f95668c83dfb6401762bb2d01a262")
    var x2 = hex.decode[BLOCK_SIZE]("d1a24ddd2721d006bbe45f20d3c9f362")

    var poly = poly_init(h)
    poly.update(x1)
    poly.update(x2)

    assert_equal(
        poly^.finalize(),
        hex.decode[T.TAG_SIZE]("f7a3b47b846119fae5b7866cf5e5b77e"),
    )


# Test vectors from RFC 8452 Appendix A.
# <https://www.rfc-editor.org/rfc/rfc8452#appendix-A>
def test_polyval_test_vector() raises:
    @parameter
    def polyval_cpu(h: InlineArray[UInt8, BLOCK_SIZE]) -> PolyvalCpu:
        return PolyvalCpu(h)

    check_polyval_test_vector[PolyvalCpu, polyval_cpu]()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
