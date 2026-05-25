from std.gpu.host import DeviceContext, DeviceBuffer
from std.memory import memcpy

from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher
from mojo_crypto.errors import GpuContextError, BlockSizeError

from .cpu.cipher import cipher as cpu_cipher, decipher as cpu_decipher
from .gpu.cipher import cipher as gpu_cipher, decipher as gpu_decipher
from .expand import key_expansion
from .common import Nb, BLOCK_SIZE, SBOX, SBOX_INV


# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
struct Aes[KeySize: Int](BlockCipher, GpuBlockCipher, ImplicitlyDestructible):
    comptime Nk: Int = Self.KeySize // 4
    comptime Nr: Int = Self.Nk + 6
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]
    var _gpu: Optional[AesGpuSetup]

    def __init__(
        out self,
        key: InlineArray[UInt8, Self.KeySize],
        ctx: Optional[DeviceContext] = None,
    ) raises:
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"
        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)
        if ctx:
            self._gpu = AesGpuSetup(ctx.value(), self.w)
        else:
            self._gpu = None

    def encrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        _encrypt_cpu[Self.Nr](data, self.w)

    def decrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        _decrypt_cpu[Self.Nr](data, self.w)

    def encrypt[
        o: MutOrigin
    ](self, ctx: DeviceContext, data: Span[UInt8, o]) raises:
        if not self._gpu:
            raise GpuContextError()
        _encrypt_gpu[Self.Nr](
            ctx, self._gpu.value().w, self._gpu.value().sbox, data
        )

    def decrypt[
        o: MutOrigin
    ](self, ctx: DeviceContext, data: Span[UInt8, o]) raises:
        if not self._gpu:
            raise GpuContextError()
        _decrypt_gpu[Self.Nr](
            ctx, self._gpu.value().w, self._gpu.value().sbox_inv, data
        )


struct AesGpuSetup(ImplicitlyDestructible, Movable):
    var w: DeviceBuffer[DType.uint32]
    var sbox: DeviceBuffer[DType.uint32]
    var sbox_inv: DeviceBuffer[DType.uint8]

    def __init__[
        WordsSize: Int
    ](out self, ctx: DeviceContext, w: InlineArray[UInt32, WordsSize]) raises:
        self.w = ctx.enqueue_create_buffer[DType.uint32](WordsSize)
        self.w.enqueue_copy_from(w)

        self.sbox = ctx.enqueue_create_buffer[DType.uint32](256)
        self.sbox.enqueue_copy_from(SBOX.unsafe_ptr())

        self.sbox_inv = ctx.enqueue_create_buffer[DType.uint8](256)
        self.sbox_inv.enqueue_copy_from(SBOX_INV.unsafe_ptr())


def _check_block_aligned(size: Int) raises:
    if size % BLOCK_SIZE != 0:
        raise BlockSizeError(size)


def _encrypt_cpu[
    Nr: Int, WordsSize: Int, o: MutOrigin
](data: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]) raises:
    _check_block_aligned(len(data))
    var block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
    for i in range(len(data) // BLOCK_SIZE):
        memcpy(
            dest=block.unsafe_ptr(),
            src=data.unsafe_ptr() + i * BLOCK_SIZE,
            count=BLOCK_SIZE,
        )
        cpu_cipher[Nr=Nr](block, w)
        memcpy(
            dest=data.unsafe_ptr() + i * BLOCK_SIZE,
            src=block.unsafe_ptr(),
            count=BLOCK_SIZE,
        )


def _decrypt_cpu[
    Nr: Int, WordsSize: Int, o: MutOrigin
](data: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]) raises:
    _check_block_aligned(len(data))
    var block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
    for i in range(len(data) // BLOCK_SIZE):
        memcpy(
            dest=block.unsafe_ptr(),
            src=data.unsafe_ptr() + i * BLOCK_SIZE,
            count=BLOCK_SIZE,
        )
        cpu_decipher[Nr=Nr](block, w)
        memcpy(
            dest=data.unsafe_ptr() + i * BLOCK_SIZE,
            src=block.unsafe_ptr(),
            count=BLOCK_SIZE,
        )


def _encrypt_gpu[
    Nr: Int, o: MutOrigin
](
    ctx: DeviceContext,
    w: DeviceBuffer[DType.uint32],
    sbox: DeviceBuffer[DType.uint32],
    data: Span[UInt8, o],
) raises:
    _check_block_aligned(len(data))
    var size = len(data)
    var num_blocks = size // BLOCK_SIZE
    comptime kernel = gpu_cipher[Nr]

    var buf = ctx.enqueue_create_buffer[DType.uint8](size)
    buf.enqueue_copy_from(data.unsafe_ptr())

    ctx.enqueue_function[kernel, kernel](
        buf,
        w,
        sbox,
        grid_dim=num_blocks,
        block_dim=BLOCK_SIZE,
    )

    buf.enqueue_copy_to(data.unsafe_ptr())


def _decrypt_gpu[
    Nr: Int, o: MutOrigin
](
    ctx: DeviceContext,
    w: DeviceBuffer[DType.uint32],
    sbox_inv: DeviceBuffer[DType.uint8],
    data: Span[UInt8, o],
) raises:
    _check_block_aligned(len(data))
    var size = len(data)
    var num_blocks = size // BLOCK_SIZE
    comptime kernel = gpu_decipher[Nr]

    var buf = ctx.enqueue_create_buffer[DType.uint8](size)
    buf.enqueue_copy_from(data.unsafe_ptr())

    ctx.enqueue_function[kernel, kernel](
        buf,
        w,
        sbox_inv,
        grid_dim=num_blocks,
        block_dim=BLOCK_SIZE,
    )
    buf.enqueue_copy_to(data.unsafe_ptr())
