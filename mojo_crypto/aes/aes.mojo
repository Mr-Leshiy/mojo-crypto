from std.gpu.host import DeviceContext, DeviceBuffer

from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher
from mojo_crypto.errors import GpuContextError

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

    def encrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) -> InlineArray[UInt8, BLOCK_SIZE]:
        var state = block
        _encrypt_cpu[BLOCK_SIZE, Self.Nr](state, self.w)
        return state

    def encrypt[
        Size: Int
    ](self, data: InlineArray[UInt8, Size]) -> InlineArray[UInt8, Size]:
        var result = data
        _encrypt_cpu[Size, Self.Nr](result, self.w)
        return result

    def decrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) -> InlineArray[UInt8, BLOCK_SIZE]:
        var state = block
        _decrypt_cpu[BLOCK_SIZE, Self.Nr](state, self.w)
        return state

    def decrypt[
        Size: Int
    ](self, data: InlineArray[UInt8, Size]) -> InlineArray[UInt8, Size]:
        var result = data
        _decrypt_cpu[Size, Self.Nr](result, self.w)
        return result

    def encrypt_block(
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        if not self._gpu:
            raise GpuContextError()
        return _encrypt_gpu[BLOCK_SIZE, Self.Nr](
            ctx, self._gpu.value().w, self._gpu.value().sbox, block
        )

    def encrypt[
        Size: Int
    ](
        self, ctx: DeviceContext, data: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        if not self._gpu:
            raise GpuContextError()
        return _encrypt_gpu[Size, Self.Nr](
            ctx, self._gpu.value().w, self._gpu.value().sbox, data
        )

    def decrypt_block(
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        if not self._gpu:
            raise GpuContextError()
        return _decrypt_gpu[BLOCK_SIZE, Self.Nr](
            ctx, self._gpu.value().w, self._gpu.value().sbox_inv, block
        )

    def decrypt[
        Size: Int
    ](
        self, ctx: DeviceContext, data: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        if not self._gpu:
            raise GpuContextError()
        return _decrypt_gpu[Size, Self.Nr](
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


def _encrypt_cpu[
    Size: Int, Nr: Int, WordsSize: Int
](mut data: InlineArray[UInt8, Size], w: InlineArray[UInt32, WordsSize]):
    comptime assert (
        Size % BLOCK_SIZE == 0
    ), "input size must be a multiple of 16 (BLOCK_SIZE)"
    for i in range(Size // BLOCK_SIZE):
        var block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
        for j in range(BLOCK_SIZE):
            block[j] = data[i * BLOCK_SIZE + j]
        cpu_cipher[Nr=Nr](block, w)
        for j in range(BLOCK_SIZE):
            data[i * BLOCK_SIZE + j] = block[j]


def _decrypt_cpu[
    Size: Int, Nr: Int, WordsSize: Int
](mut data: InlineArray[UInt8, Size], w: InlineArray[UInt32, WordsSize]):
    comptime assert (
        Size % BLOCK_SIZE == 0
    ), "input size must be a multiple of 16 (BLOCK_SIZE)"
    for i in range(Size // BLOCK_SIZE):
        var block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
        for j in range(BLOCK_SIZE):
            block[j] = data[i * BLOCK_SIZE + j]
        cpu_decipher[Nr=Nr](block, w)
        for j in range(BLOCK_SIZE):
            data[i * BLOCK_SIZE + j] = block[j]


def _encrypt_gpu[
    Size: Int, Nr: Int
](
    ctx: DeviceContext,
    w: DeviceBuffer[DType.uint32],
    sbox: DeviceBuffer[DType.uint32],
    data: InlineArray[UInt8, Size],
) raises -> InlineArray[UInt8, Size]:
    comptime assert (
        Size % BLOCK_SIZE == 0
    ), "input size must be a multiple of 16 (BLOCK_SIZE)"
    comptime num_blocks = Size // BLOCK_SIZE
    comptime kernel = gpu_cipher[Nr]

    var result = InlineArray[UInt8, Size](uninitialized=True)
    var buf = ctx.enqueue_create_buffer[DType.uint8](Size)
    buf.enqueue_copy_from(data)

    ctx.enqueue_function[kernel, kernel](
        buf,
        w,
        sbox,
        grid_dim=num_blocks,
        block_dim=BLOCK_SIZE,
    )

    buf.enqueue_copy_to(result.unsafe_ptr())
    return result


def _decrypt_gpu[
    Size: Int, Nr: Int
](
    ctx: DeviceContext,
    w: DeviceBuffer[DType.uint32],
    sbox_inv: DeviceBuffer[DType.uint8],
    data: InlineArray[UInt8, Size],
) raises -> InlineArray[UInt8, Size]:
    comptime assert (
        Size % BLOCK_SIZE == 0
    ), "input size must be a multiple of 16 (BLOCK_SIZE)"
    comptime num_blocks = Size // BLOCK_SIZE
    comptime kernel = gpu_decipher[Nr]

    var result = InlineArray[UInt8, Size](uninitialized=True)
    var buf = ctx.enqueue_create_buffer[DType.uint8](Size)
    buf.enqueue_copy_from(data)

    ctx.enqueue_function[kernel, kernel](
        buf,
        w,
        sbox_inv,
        grid_dim=num_blocks,
        block_dim=BLOCK_SIZE,
    )
    buf.enqueue_copy_to(result.unsafe_ptr())
    return result
