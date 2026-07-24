from std.testing import assert_equal, TestSuite
from std.sys.info import CompilationTarget

from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.utils.hex import hex_decode
from mojo_crypto.universal_hashes.traits import UniversalHashable
from mojo_crypto.universal_hashes.polyval import (
    PolyvalNaive,
    PolyvalAarch64,
    PolyvalX86,
)


def check_polyval_test_vector[
    T: UniversalHashable & Movable & ImplicitlyDestructible,
]() raises:
    var h = hex_decode[T.KEY_SIZE]("25629347589242761d31f826ba4b757b")
    var x1 = hex_decode[T.BLOCK_SIZE]("4f4f95668c83dfb6401762bb2d01a262")
    var x2 = hex_decode[T.BLOCK_SIZE]("d1a24ddd2721d006bbe45f20d3c9f362")

    var poly = T(h)
    poly.update(x1)
    poly.update(x2)

    assert_equal(
        poly^.finalize(),
        hex_decode[T.TAG_SIZE]("f7a3b47b846119fae5b7866cf5e5b77e"),
    )


# Test vectors from RFC 8452 Appendix A.
# <https://www.rfc-editor.org/rfc/rfc8452#appendix-A>
def test_polyval_test_vector() raises:
    check_polyval_test_vector[PolyvalNaive]()

    comptime if target_triple_contains_any(["aarch64", "arm64"]):
        check_polyval_test_vector[PolyvalAarch64]()

    comptime if target_triple_contains_any(["x86_64"]):
        check_polyval_test_vector[PolyvalX86]()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
