from std.testing import assert_equal, assert_true, assert_raises, TestSuite

from mojo_crypto.utils import hex_encode, hex_decode


def test_hex_encode() raises:
    var data: List[UInt8] = [0x00, 0xFF, 0xAB, 0x12]
    assert_equal(hex_encode(Span(data)), "00ffab12")

    data = [0x10, 0xAB, 0xCD, 0xEF]
    assert_equal(hex_encode(Span(data)), "10abcdef")

    data = []
    assert_equal(hex_encode(Span(data)), "")


def test_hex_decode() raises:
    var result = hex_decode("00ffab12")
    var expected: List[UInt8] = [0x00, 0xFF, 0xAB, 0x12]
    assert_true(result == expected)

    result = hex_decode("DEADBEEF")
    expected = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_true(result == expected)

    result = hex_decode("DeAdBeEf")
    expected = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_true(result == expected)

    var data: List[UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0xFE, 0xFF]
    var decoded = hex_decode(hex_encode(Span(data)))
    assert_true(decoded == data)

    var expected_fixed: InlineArray[UInt8, 4] = [0x00, 0xFF, 0xAB, 0x12]
    assert_equal(hex_decode[4]("00ffab12"), expected_fixed)

    expected_fixed = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_equal(hex_decode[4]("DeAdBeEf"), expected_fixed)


def test_invalid_hex_decode() raises:
    with assert_raises():
        _ = hex_decode("abc")

    with assert_raises():
        _ = hex_decode("0g")

    with assert_raises():
        _ = hex_decode("ab0Xcd")

    with assert_raises():
        _ = hex_decode[4]("00ffab")  # too short

    with assert_raises():
        _ = hex_decode[4]("00ffab1234")  # too long

    with assert_raises():
        _ = hex_decode[4]("0g123456")  # invalid character


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
