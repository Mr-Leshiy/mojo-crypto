comptime _HEX_CHARS: StaticString = "0123456789abcdef"


@fieldwise_init
struct HexError(ImplicitlyDestructible, Writable):
    var message: String

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.message)


def hex_encode[o: Origin](data: Span[UInt8, o]) -> String:
    var result = String()
    for i in range(len(data)):
        var b = Int(data[i])
        result += String(_HEX_CHARS[byte=b >> 4])
        result += String(_HEX_CHARS[byte=b & 0xF])
    return result^


def hex_decode(s: String) raises HexError -> List[UInt8]:
    if s.byte_length() % 2 != 0:
        raise HexError(
            "hex string length must be even; got {}".format(s.byte_length())
        )
    var n = s.byte_length() // 2
    var result = List[UInt8](capacity=n)
    var ptr = s.unsafe_ptr()
    for i in range(n):
        result.append(
            (_nibble(ptr[2 * i], 2 * i) << 4)
            | _nibble(ptr[2 * i + 1], 2 * i + 1)
        )
    return result^


@always_inline
def _nibble(c: UInt8, pos: Int) raises HexError -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    raise HexError("invalid hex character at position {}".format(pos))
