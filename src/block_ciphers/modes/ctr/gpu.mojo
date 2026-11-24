from max.gpu import thread_idx, block_idx, block_dim
from max.gpu.host import DeviceBuffer
from std.math import ceildiv
from std.memory import unsafe_memcpy
from std.sys.info import CompilationTarget
from warp import Context

from ....utils import yield_now
from ...traits import (
    GpuBlockCipherDecryptable,
    GpuBlockCipherEncryptable,
)
from .common import _check_params


struct GpuCtrMode[
    C: GpuBlockCipherEncryptable
    & GpuBlockCipherDecryptable
    & Movable
    & Deinitable,
    SIZE: Int = C.BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](
    Deinitable,
    GpuBlockCipherDecryptable,
    GpuBlockCipherEncryptable,
    Movable,
):
    """Counter (CTR) block cipher mode over an async (device-backed) cipher.

    NIST SP 800-38A, Section 6.5:
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    Each keystream block is produced by its own awaited cipher call. `SIZE`
    and `BIG_ENDIAN` are as in `CtrMode`.
    """

    comptime BLOCK_SIZE: Int = Self.C.BLOCK_SIZE

    var _cipher: Self.C
    var _ctr: DeviceBuffer[DType.uint8]

    def __init__(
        out self,
        var cipher: Self.C,
        var ctr: DeviceBuffer[DType.uint8],
    ):
        _check_params[Self.BLOCK_SIZE, Self.SIZE]()
        debug_assert(len(ctr) == Self.BLOCK_SIZE, "counter must be one block")

        self._cipher = cipher^
        self._ctr = ctr^

    def encrypt[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        self._apply(ctx, data)

    def decrypt[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        self._apply(ctx, data)

    def _apply[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        """XOR the keystream over `data` in place; encryption and decryption
        are the same operation.
        """
        var blocks = ceildiv(len(data), Self.BLOCK_SIZE)
        var counters = ctx.gpu_ctx().enqueue_create_buffer[DType.uint8](
            (blocks + 1) * Self.BLOCK_SIZE
        )

        ctx.gpu_ctx().enqueue_function[
            _fill_counters_kernel[Self.BLOCK_SIZE, Self.SIZE, Self.BIG_ENDIAN]
        ](counters, self._ctr, grid_dim=blocks + 1, block_dim=Self.BLOCK_SIZE)
        ctx.gpu_ctx().enqueue_copy(
            self._ctr,
            counters.create_sub_buffer[DType.uint8](
                blocks * Self.BLOCK_SIZE, Self.BLOCK_SIZE
            ),
        )

        var keystream = counters.create_sub_buffer[DType.uint8](
            0, blocks * Self.BLOCK_SIZE
        )
        self._cipher.encrypt(ctx, keystream)
        ctx.gpu_ctx().enqueue_function[_xor_keystream_kernel](
            data,
            keystream,
            Int64(len(data)),
            grid_dim=blocks,
            block_dim=Self.BLOCK_SIZE,
        )

    __async def encrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        __await yield_now(ctx)

        var device = ctx.enqueue_device_buffer(data)
        self._apply(ctx, device)
        var host = ctx.enqueue_host_buffer(device)
        __await ctx.synchronize()
        unsafe_memcpy(
            dest=data.unsafe_ptr(), src=host.unsafe_ptr(), count=len(data)
        )

    __async def decrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        __await yield_now(ctx)

        var device = ctx.enqueue_device_buffer(data)
        self._apply(ctx, device)
        var host = ctx.enqueue_host_buffer(device)
        __await ctx.synchronize()
        unsafe_memcpy(
            dest=data.unsafe_ptr(), src=host.unsafe_ptr(), count=len(data)
        )


# Thread j of block b writes byte j of counter block b: the initial counter
# plus b, carried through the `SIZE`-byte counter field only, as in
# `_increment_ctr`.
def _fill_counters_kernel[
    BLOCK_SIZE: Int, SIZE: Int, BIG_ENDIAN: Bool
](
    counters: Pointer[Scalar[DType.uint8], MutAnyOrigin],
    ctr: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    var j = thread_idx.x
    var b = block_idx.x
    var byte = ctr[unsafe_offset=j]
    var carry = b
    comptime if BIG_ENDIAN:
        for k in range(BLOCK_SIZE - 1, BLOCK_SIZE - SIZE - 1, -1):
            var sum = Int(ctr[unsafe_offset=k]) + carry
            if k == j:
                byte = UInt8(sum & 0xFF)
            carry = sum >> 8
    else:
        for k in range(SIZE):
            var sum = Int(ctr[unsafe_offset=k]) + carry
            if k == j:
                byte = UInt8(sum & 0xFF)
            carry = sum >> 8
    counters[unsafe_offset=b * BLOCK_SIZE + j] = byte


def _xor_keystream_kernel(
    data: Pointer[Scalar[DType.uint8], MutAnyOrigin],
    keystream: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
    length: Int64,
):
    var i = block_idx.x * block_dim.x + thread_idx.x
    if Int64(i) < length:
        data[unsafe_offset=i] ^= keystream[unsafe_offset=i]
