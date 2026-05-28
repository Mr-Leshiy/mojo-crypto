from std.testing import assert_equal, assert_true, assert_raises, TestSuite

from mojo_crypto.containers.encoding import HexError, hex_encode, hex_decode


def test_hex_encode() raises:
    var data: List[UInt8] = [0x00, 0xFF, 0xAB, 0x12]
    assert_equal(hex_encode(Span(data)), "00ffab12")


def test_hex_encode_lowercase() raises:
    var data: List[UInt8] = [0x10, 0xAB, 0xCD, 0xEF]
    assert_equal(hex_encode(Span(data)), "10abcdef")


def test_hex_encode_empty() raises:
    var data: List[UInt8] = []
    assert_equal(hex_encode(Span(data)), "")


def test_hex_decode() raises:
    var result = hex_decode("00ffab12")
    var expected: List[UInt8] = [0x00, 0xFF, 0xAB, 0x12]
    assert_true(result == expected)


def test_hex_decode_uppercase() raises:
    var result = hex_decode("DEADBEEF")
    var expected: List[UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_true(result == expected)


def test_hex_decode_mixed_case() raises:
    var result = hex_decode("DeAdBeEf")
    var expected: List[UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
    assert_true(result == expected)


def test_hex_round_trip() raises:
    var data: List[UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0xFE, 0xFF]
    var decoded = hex_decode(hex_encode(Span(data)))
    assert_true(decoded == data)


def test_hex_decode_odd_length_raises() raises:
    with assert_raises():
        _ = hex_decode("abc")


def test_hex_decode_invalid_char_raises() raises:
    with assert_raises():
        _ = hex_decode("0g")


def test_hex_decode_invalid_char_mid_raises() raises:
    with assert_raises():
        _ = hex_decode("ab0Xcd")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
