from std.testing import assert_equal, assert_true, assert_raises, TestSuite

from mojo_crypto.containers.encoding import Hex, Encodable, Decodable


def check_hex[H: Encodable & Decodable](hex: H) raises:
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

    with assert_raises():
        _ = hex.decode("abc")

    with assert_raises():
        _ = hex.decode("0g")

    with assert_raises():
        _ = hex.decode("ab0Xcd")


def test_hex() raises:
    check_hex(Hex())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
