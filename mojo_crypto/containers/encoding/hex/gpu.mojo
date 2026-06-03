from std.gpu.host import DeviceContext, DeviceBuffer
from std.gpu.memory import AddressSpace
from std.gpu import thread_idx, block_idx

from .common import HEX_CHARS, HexError

struct HexGpu[BLOCK_SIZE: Int = 256](Decodable, Encodable, ImplicitlyDestructible, Movable):
    """GPU-accelerated hex encoder/decoder.

    Parameters:
        BLOCK_SIZE: Number of threads per GPU thread block. Each thread decodes
            one byte (two hex characters). Defaults to 256.
    """
    var ctx: DeviceContext

    def __init__(out self, ctx: DeviceContext):
        self.ctx = ctx

    def encode[o: Origin](self, data: Span[UInt8, o]) -> String:
        var result = String()
        for i in range(len(data)):
            var b = Int(data[i])
            result += String(HEX_CHARS[byte=b >> 4])
            result += String(HEX_CHARS[byte=b & 0xF])
        return result^

    def decode(self, s: String) raises -> List[UInt8]:
        """Assumes s is a valid hex string. Invalid characters produce 0 bytes."""
        if s.byte_length() % 2 != 0:
            raise HexError(
                "hex string length must be even; got {}".format(s.byte_length())
            )
        var n = s.byte_length() // 2
        var num_blocks = n // Self.BLOCK_SIZE + 1

        var res_buf = self.ctx.enqueue_create_buffer[DType.uint8](n)
        var hex_s = self.ctx.enqueue_create_buffer[DType.uint8](s.byte_length())
        hex_s.enqueue_copy_from(s.unsafe_ptr())

        comptime kernel = decode[Self.BLOCK_SIZE]
        self.ctx.enqueue_function[kernel, kernel](
            res_buf,
            hex_s,
            n,
            grid_dim=num_blocks,
            block_dim=Self.BLOCK_SIZE,
        )

        self.ctx.synchronize()
        var result = List[UInt8](capacity=n)
        result.resize(n, 0)
        res_buf.enqueue_copy_to(result.unsafe_ptr())
        return result^


def decode[BLOCK_SIZE: Int](
    res: UnsafePointer[Scalar[DType.uint8], MutAnyOrigin],
    hex_s: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    n: Int,
):
    var i = block_idx.x * BLOCK_SIZE + thread_idx.x
    if i < n:
        left = _nibble(hex_s[2 * i], 2 * i) << 4
        right = _nibble(hex_s[2 * i + 1], 2 * i + 1)
        res[i] = left | right


@always_inline
def _nibble(c: UInt8, pos: Int) -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    return 0 
