from max.gpu import thread_idx, block_idx
from max.gpu.host import DeviceBuffer
from std.memory import unsafe_memcpy
from std.sys.info import CompilationTarget
from warp import Context

from ...traits import (
    GpuBlockCipherDecryptable,
    GpuBlockCipherEncryptable,
)
from ...errors import BlockSizeError
from ....utils import yield_now


struct GpuCbcMode[
    Cipher: GpuBlockCipherEncryptable
    & GpuBlockCipherDecryptable
    & Movable
    & Deinitable
](
    Deinitable,
    GpuBlockCipherDecryptable,
    GpuBlockCipherEncryptable,
    Movable,
):
    """CBC block cipher mode of operation over an async (device-backed) cipher.

    See [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf),
    Section 6.2.

    The chaining value lives in a device buffer, so the calls on a
    `DeviceBuffer` only enqueue work. Not `Copyable`: a copy of a device buffer
    would share the chaining value with the original.
    """

    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _iv: DeviceBuffer[DType.uint8]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        var iv: DeviceBuffer[DType.uint8],
    ):
        """Initialize from an already-keyed cipher and a one-block device IV.

        `iv` is overwritten as the mode advances.
        """
        debug_assert(len(iv) == Self.BLOCK_SIZE, "IV must be one block")
        self._cipher = cipher^
        self._iv = iv^

    def encrypt[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        var blocks = len(data) // Self.BLOCK_SIZE
        # `prev` is only a handle to a device buffer, so assigning it copies no
        # device memory.
        var prev = self._iv
        for i in range(blocks):
            var block = data.create_sub_buffer[DType.uint8](
                i * Self.BLOCK_SIZE, Self.BLOCK_SIZE
            )
            _launch_xor_block[Self.BLOCK_SIZE](ctx, block, prev, blocks=1)
            self._cipher.encrypt(ctx, block)
            prev = block

        # The last ciphertext block chains the next call.
        ctx.gpu_ctx().enqueue_copy(self._iv, prev)

    def decrypt[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        # The ciphertext is what each block is chained to, and the cipher
        # overwrites it in place.
        var blocks = len(data) // Self.BLOCK_SIZE
        var ciphertext = ctx.gpu_ctx().enqueue_create_buffer[DType.uint8](
            len(data)
        )
        ctx.gpu_ctx().enqueue_copy(ciphertext, data)

        self._cipher.decrypt(ctx, data)
        _launch_xor_chain[Self.BLOCK_SIZE](
            ctx, data, ciphertext, self._iv, blocks
        )

        # The last ciphertext block chains the next call.
        ctx.gpu_ctx().enqueue_copy(
            self._iv,
            ciphertext.create_sub_buffer[DType.uint8](
                len(data) - Self.BLOCK_SIZE, Self.BLOCK_SIZE
            ),
        )

    __async def encrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        __await yield_now(ctx)
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        var device = ctx.enqueue_device_buffer(data)
        self.encrypt(ctx, device)
        var host = ctx.enqueue_host_buffer(device)
        __await ctx.synchronize()
        unsafe_memcpy(
            dest=data.unsafe_ptr(), src=host.unsafe_ptr(), count=len(data)
        )

    __async def decrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        __await yield_now(ctx)
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        var device = ctx.enqueue_device_buffer(data)
        self.decrypt(ctx, device)
        var host = ctx.enqueue_host_buffer(device)
        __await ctx.synchronize()
        unsafe_memcpy(
            dest=data.unsafe_ptr(), src=host.unsafe_ptr(), count=len(data)
        )


def _launch_xor_block[
    target: CompilationTarget, //, BLOCK_SIZE: Int
](
    ctx: Context[target],
    block: DeviceBuffer[DType.uint8],
    value: DeviceBuffer[DType.uint8],
    blocks: Int,
) raises:
    ctx.gpu_ctx().enqueue_function[_xor_block_kernel](
        block, value, grid_dim=blocks, block_dim=BLOCK_SIZE
    )


def _launch_xor_chain[
    target: CompilationTarget, //, BLOCK_SIZE: Int
](
    ctx: Context[target],
    data: DeviceBuffer[DType.uint8],
    ciphertext: DeviceBuffer[DType.uint8],
    iv: DeviceBuffer[DType.uint8],
    blocks: Int,
) raises:
    ctx.gpu_ctx().enqueue_function[_xor_chain_kernel[BLOCK_SIZE]](
        data, ciphertext, iv, grid_dim=blocks, block_dim=BLOCK_SIZE
    )


# block[i] ^= value[i] for the one block this launch covers.
def _xor_block_kernel(
    block: Pointer[Scalar[DType.uint8], MutAnyOrigin],
    value: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    block[unsafe_offset=thread_idx.x] ^= value[unsafe_offset=thread_idx.x]


# data[b] ^= ciphertext[b - 1], or the IV for the first block.
def _xor_chain_kernel[
    BLOCK_SIZE: Int
](
    data: Pointer[Scalar[DType.uint8], MutAnyOrigin],
    ciphertext: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
    iv: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    var j = thread_idx.x
    var i = block_idx.x * BLOCK_SIZE + j
    if block_idx.x == 0:
        data[unsafe_offset=i] ^= iv[unsafe_offset=j]
    else:
        data[unsafe_offset=i] ^= ciphertext[unsafe_offset=i - BLOCK_SIZE]
