from std.testing import assert_equal, TestSuite

from mojo_crypto.containers.encoding import Hex
from mojo_crypto.utils import load_be


def test_load_be() raises:
    var hex = Hex()

    assert_equal(
        load_be[DType.uint32](Span(hex.decode[4]("00000000"))), UInt32(0)
    )
    assert_equal(
        load_be[DType.uint32](Span(hex.decode[4]("ffffffff"))),
        UInt32(0xFFFFFFFF),
    )
    assert_equal(
        load_be[DType.uint32](Span(hex.decode[4]("01020304"))),
        UInt32(0x01020304),
    )

    assert_equal(
        load_be[DType.uint64](Span(hex.decode[8]("0000000000000000"))),
        UInt64(0),
    )
    assert_equal(
        load_be[DType.uint64](Span(hex.decode[8]("ffffffffffffffff"))),
        UInt64(0xFFFFFFFFFFFFFFFF),
    )
    assert_equal(
        load_be[DType.uint64](Span(hex.decode[8]("0102030405060708"))),
        UInt64(0x0102030405060708),
    )

    # A span shorter than the full word width is still fully consumed —
    # useful for reading a truncated/partial word.
    assert_equal(
        load_be[DType.uint32](Span(hex.decode[2]("0102"))), UInt32(0x0102)
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
