from std.testing import assert_equal, assert_true, assert_raises, TestSuite
from std.gpu.host import DeviceContext
from std.sys import has_accelerator

from mojo_crypto.containers.encoding import Hex, HexGpu, Encodable, Decodable


def check_valid_hex[H: Encodable & Decodable](hex: H) raises:
    var data: List[UInt8] = [0x00, 0xFF, 0xAB, 0x12]
    assert_equal(hex.encode(Span(data)), "00ffab12")

    data = [0x10, 0xAB, 0xCD, 0xEF]
    assert_equal(hex.encode(Span(data)), "10abcdef")

    data = []
    assert_equal(hex.encode(Span(data)), "")

    var result = hex.decode("00ffab12")
    var expected: List[UInt8] = [0x00, 0xFF, 0xAB, 0x12]
    assert_true(result == expected)

    result = hex.decode("DEADBEEF")
    expected = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_true(result == expected)

    result = hex.decode("DeAdBeEf")
    expected = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_true(result == expected)

    data = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0xFE, 0xFF]
    decoded = hex.decode(hex.encode(Span(data)))
    assert_true(decoded == data)

    var expected_fixed: InlineArray[UInt8, 4] = [0x00, 0xFF, 0xAB, 0x12]
    assert_equal(hex.decode[4]("00ffab12"), expected_fixed)

    expected_fixed = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_equal(hex.decode[4]("DeAdBeEf"), expected_fixed)


def check_invalid_hex[H: Encodable & Decodable](hex: H) raises:
    with assert_raises():
        _ = hex.decode("abc")

    with assert_raises():
        _ = hex.decode("0g")

    with assert_raises():
        _ = hex.decode("ab0Xcd")

    with assert_raises():
        _ = hex.decode[4]("00ffab")  # too short

    with assert_raises():
        _ = hex.decode[4]("00ffab1234")  # too long

    with assert_raises():
        _ = hex.decode[4]("0g123456")  # invalid character


def test_hex() raises:
    check_valid_hex(Hex())
    check_invalid_hex(Hex())

    comptime if has_accelerator():
        with DeviceContext() as ctx:
            check_valid_hex(HexGpu(ctx))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
