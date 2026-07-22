from std.gpu.host import DeviceContext, DeviceBuffer
from std.gpu import thread_idx, block_idx

from ._common import HexError


struct HexGpu[BLOCK_SIZE: Int = 256](
    Decodable, Encodable, ImplicitlyDestructible, Movable
):
    """GPU-accelerated hex encoder/decoder. Experimental — for study purposes only.

    Hex encoding/decoding is memory-bandwidth-bound and operates on very small
    units of work per thread. The kernel launch overhead and host↔device transfers
    make this slower than HexCpu for typical input sizes. Benchmark against
    HexCpu before using in production.

    Parameters:
        BLOCK_SIZE: Number of threads per GPU thread block. Each thread encodes
            one byte (two hex characters) or decodes one byte pair. Defaults to 256.
    """

    var ctx: DeviceContext

    def __init__(out self, ctx: DeviceContext):
        self.ctx = ctx

    def encode[o: Origin](self, data: Span[UInt8, o]) raises -> String:
        var n = len(data)
        var out_len = n * 2
        var num_blocks = n // Self.BLOCK_SIZE + 1

        var in_buf = self.ctx.enqueue_create_buffer[DType.uint8](n)
        var out_buf = self.ctx.enqueue_create_buffer[DType.uint8](out_len)
        in_buf.enqueue_copy_from(data.unsafe_ptr())

        comptime kernel = _encode_kernel[Self.BLOCK_SIZE]
        self.ctx.enqueue_function[kernel, kernel](
            out_buf,
            in_buf,
            n,
            grid_dim=num_blocks,
            block_dim=Self.BLOCK_SIZE,
        )

        self.ctx.synchronize()
        var bytes = List[UInt8](capacity=out_len)
        bytes.resize(out_len, 0)
        out_buf.enqueue_copy_to(bytes.unsafe_ptr())
        return String(StringSlice(unsafe_from_utf8=Span[UInt8](bytes)))

    def decode(self, s: String) raises -> List[UInt8]:
        """Assumes s is a valid hex string. Invalid characters produce 0 bytes.
        """
        if s.byte_length() % 2 != 0:
            raise HexError(
                "hex string length must be even; got {}".format(s.byte_length())
            )
        var n = s.byte_length() // 2
        var num_blocks = n // Self.BLOCK_SIZE + 1

        var out_buf = self.ctx.enqueue_create_buffer[DType.uint8](n)
        var hex_s = self.ctx.enqueue_create_buffer[DType.uint8](s.byte_length())
        hex_s.enqueue_copy_from(s.unsafe_ptr())

        comptime kernel = _decode_kernel[Self.BLOCK_SIZE]
        self.ctx.enqueue_function[kernel, kernel](
            out_buf,
            hex_s,
            n,
            grid_dim=num_blocks,
            block_dim=Self.BLOCK_SIZE,
        )

        self.ctx.synchronize()
        var result = List[UInt8](capacity=n)
        result.resize(n, 0)
        out_buf.enqueue_copy_to(result.unsafe_ptr())
        return result^

    def decode[SIZE: Int](self, s: String) raises -> InlineArray[UInt8, SIZE]:
        """Assumes s is a valid hex string. Invalid characters produce 0 bytes.
        """
        if s.byte_length() != SIZE * 2:
            raise HexError(
                "expected hex string of length {}; got {}".format(
                    SIZE * 2, s.byte_length()
                )
            )
        var num_blocks = SIZE // Self.BLOCK_SIZE + 1

        var out_buf = self.ctx.enqueue_create_buffer[DType.uint8](SIZE)
        var hex_s = self.ctx.enqueue_create_buffer[DType.uint8](s.byte_length())
        hex_s.enqueue_copy_from(s.unsafe_ptr())

        comptime kernel = _decode_kernel[Self.BLOCK_SIZE]
        self.ctx.enqueue_function[kernel, kernel](
            out_buf,
            hex_s,
            SIZE,
            grid_dim=num_blocks,
            block_dim=Self.BLOCK_SIZE,
        )

        self.ctx.synchronize()
        var result = InlineArray[UInt8, SIZE](uninitialized=True)
        out_buf.enqueue_copy_to(result.unsafe_ptr())
        return result^


# Each thread encodes one input byte into two ASCII hex characters.
def _encode_kernel[
    BLOCK_SIZE: Int
](
    res: UnsafePointer[Scalar[DType.uint8], MutAnyOrigin],
    data: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    n: Int,
):
    var i = block_idx.x * BLOCK_SIZE + thread_idx.x
    if i < n:
        var b = data[i]
        res[2 * i] = _hex_char(b >> 4)
        res[2 * i + 1] = _hex_char(b & 0x0F)


# Each thread decodes two ASCII hex characters into one output byte.
def _decode_kernel[
    BLOCK_SIZE: Int
](
    res: UnsafePointer[Scalar[DType.uint8], MutAnyOrigin],
    hex_s: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    n: Int,
):
    var i = block_idx.x * BLOCK_SIZE + thread_idx.x
    if i < n:
        left = _nibble(hex_s[2 * i]) << 4
        right = _nibble(hex_s[2 * i + 1])
        res[i] = left | right


@always_inline
def _hex_char(nibble: UInt8) -> UInt8:
    if nibble < 10:
        return nibble + 48  # '0'..'9'
    return nibble + 87  # 'a'..'f'  (97 - 10)


@always_inline
def _nibble(c: UInt8) -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    return 0
