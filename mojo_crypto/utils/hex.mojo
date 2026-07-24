comptime HEX_CHARS: StaticString = "0123456789abcdef"


@fieldwise_init
struct HexError(ImplicitlyDestructible, Writable):
    var message: String

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.message)


@always_inline
def hex_encode[o: Origin](data: Span[UInt8, o], mut result: String):
    """Hex-encode `data` into `result`, reusing its existing capacity."""
    result.resize(len(data) * 2)
    var dest = result.unsafe_ptr_mut()
    var hex_chars = HEX_CHARS.unsafe_ptr()
    for i in range(len(data)):
        var b = Int(data[i])
        dest[2 * i] = hex_chars[b >> 4]
        dest[2 * i + 1] = hex_chars[b & 0xF]


@always_inline
def hex_encode[o: Origin](data: Span[UInt8, o]) -> String:
    """Hex-encode `data`, returning a newly allocated string."""
    var result = String()
    hex_encode(data, result)
    return result^


@always_inline
def hex_decode(s: String) raises -> List[UInt8]:
    """Hex-decode `s` into a newly allocated, dynamically-sized list."""
    var result = List[UInt8](length=s.byte_length() // 2, fill=0)
    hex_decode(s, Span(result))
    return result^


@always_inline
def hex_decode[SIZE: Int](s: String) raises -> InlineArray[UInt8, SIZE]:
    """Hex-decode `s` into a newly allocated, fixed-size array."""
    var result = InlineArray[UInt8, SIZE](uninitialized=True)
    hex_decode(s, Span(result))
    return result^


@always_inline
def hex_decode[o: MutOrigin](s: String, result: Span[UInt8, o]) raises:
    """Hex-decode `s` into `result`, which must be exactly `len(s) // 2` bytes.
    """
    if s.byte_length() != len(result) * 2:
        raise HexError(
            "expected hex string of length {}; got {}".format(
                len(result) * 2, s.byte_length()
            )
        )
    var ptr = s.unsafe_ptr()
    for i in range(len(result)):
        result[i] = _decode_hex_byte(ptr[2 * i], ptr[2 * i + 1], 2 * i)


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
