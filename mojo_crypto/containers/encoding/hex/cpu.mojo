from .common import HEX_CHARS, HexError


@fieldwise_init
struct HexCpu(Decodable, Encodable, ImplicitlyDestructible, Movable):
    def encode[o: Origin](self, data: Span[UInt8, o]) raises -> String:
        var result = String()
        for i in range(len(data)):
            var b = Int(data[i])
            result += String(HEX_CHARS[byte=b >> 4])
            result += String(HEX_CHARS[byte=b & 0xF])
        return result^

    def decode(self, s: String) raises -> List[UInt8]:
        if s.byte_length() % 2 != 0:
            raise HexError(
                "hex string length must be even; got {}".format(s.byte_length())
            )
        var n = s.byte_length() // 2
        var result = List[UInt8](capacity=n)
        var ptr = s.unsafe_ptr()
        for i in range(n):
            result.append(_decode_hex_byte(ptr[2 * i], ptr[2 * i + 1], 2 * i))
        return result^

    def decode[SIZE: Int](self, s: String) raises -> InlineArray[UInt8, SIZE]:
        if s.byte_length() != SIZE * 2:
            raise HexError(
                "expected hex string of length {}; got {}".format(
                    SIZE * 2, s.byte_length()
                )
            )
        var result = InlineArray[UInt8, SIZE](uninitialized=True)
        var ptr = s.unsafe_ptr()
        for i in range(SIZE):
            result[i] = _decode_hex_byte(ptr[2 * i], ptr[2 * i + 1], 2 * i)
        return result^


@always_inline
def _decode_hex_byte(hi: UInt8, lo: UInt8, pos: Int) raises HexError -> UInt8:
    return (_nibble(hi, pos) << 4) | _nibble(lo, pos + 1)


@always_inline
def _nibble(c: UInt8, pos: Int) raises HexError -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    raise HexError("invalid hex character at position {}".format(pos))
