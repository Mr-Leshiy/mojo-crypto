from std.testing import assert_equal, TestSuite
from std.sys.info import CompilationTarget

from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.containers.encoding import Hex
from mojo_crypto.universal_hashes.traits import UniversalHashable
from mojo_crypto.universal_hashes.ghash import GHashCpu, GHashAarch64
from mojo_crypto.universal_hashes.ghash.generic import mulx


def check_ghash_test_vector[
    T: UniversalHashable & Movable & ImplicitlyDestructible
]() raises:
    hex = Hex()
    var h = hex.decode[T.KEY_SIZE]("25629347589242761d31f826ba4b757b")
    var x1 = hex.decode[T.BLOCK_SIZE]("4f4f95668c83dfb6401762bb2d01a262")
    var x2 = hex.decode[T.BLOCK_SIZE]("d1a24ddd2721d006bbe45f20d3c9f362")

    var ghash = T(h)
    ghash.update(x1)
    ghash.update(x2)

    assert_equal(
        ghash^.finalize(),
        hex.decode[T.TAG_SIZE]("bd9b3997046731fb96251b91f9c99d7a"),
    )


# Test vectors for GHASH from RFC 8452 Appendix A
# <https://tools.ietf.org/html/rfc8452#appendix-A>
def test_ghash_test_vector() raises:
    check_ghash_test_vector[GHashCpu]()

    comptime if target_triple_contains_any(["aarch64", "arm64"]):
        check_ghash_test_vector[GHashAarch64]()


# Test vector given in RFC 8452 Appendix A.
#
# NOTE: the vector in the RFC contains a typo which has been reported (and accepted)
# as RFC errata, so we use the corrected vector from the errata instead:
# <https://www.rfc-editor.org/errata_search.php?rfc=8452>
def test_mulx_rfc8452_vector() raises:
    hex = Hex()
    input = hex.decode[GHashCpu.BLOCK_SIZE]("9c98c04df9387ded828175a92ba652d8")
    expected = hex.decode[GHashCpu.BLOCK_SIZE](
        "3931819bf271fada0503eb52574ca572"
    )
    assert_equal(expected, mulx(input))


# Test vectors from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element/mulx.rs
def test_fe_mulx() raises:
    hex = Hex()

    MULX_TEST_VECTORS = [
        hex.decode[GHashCpu.BLOCK_SIZE]("02000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("04000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("08000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("10000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("20000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("40000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("80000000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00010000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00020000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00040000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00080000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00100000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00200000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00400000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00800000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000100000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000200000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000400000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000800000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00001000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00002000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00004000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00008000000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000001000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000002000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000004000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000008000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000010000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000020000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000040000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000080000000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000010000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000020000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000040000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000080000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000100000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000200000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000400000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000800000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000100000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000200000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000400000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000800000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000001000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000002000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000004000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000008000000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000001000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000002000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000004000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000008000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000010000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000020000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000040000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000080000000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000010000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000020000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000040000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000080000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000100000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000200000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000400000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000800000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000100000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000200000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000400000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000800000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000001000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000002000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000004000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000008000000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000001000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000002000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000004000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000008000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000010000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000020000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000040000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000080000000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000010000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000020000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000040000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000080000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000100000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000200000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000400000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000800000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000100000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000200000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000400000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000800000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000001000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000002000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000004000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000008000000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000001000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000002000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000004000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000008000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000010000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000020000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000040000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000080000000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000010000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000020000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000040000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000080000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000100000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000200000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000400000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000800000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000100"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000200"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000400"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000800"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000001000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000002000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000004000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000008000"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000001"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000002"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000004"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000008"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000010"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000020"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000040"),
        hex.decode[GHashCpu.BLOCK_SIZE]("00000000000000000000000000000080"),
        hex.decode[GHashCpu.BLOCK_SIZE]("010000000000000000000000000000c2"),
    ]
    r = hex.decode[GHashCpu.BLOCK_SIZE]("01000000000000000000000000000000")

    for vec in MULX_TEST_VECTORS:
        r = mulx(r)
        assert_equal(vec, r)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
