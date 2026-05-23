from std.gpu.host import DeviceContext, DeviceBuffer

from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

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

    def __init__(out self, key: InlineArray[UInt8, Self.KeySize]):
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"
        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)
        self._gpu = None

    def __init__(
        out self, key: InlineArray[UInt8, Self.KeySize], ctx: DeviceContext
    ) raises:
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"
        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)
        self._gpu = AesGpuSetup(ctx, self.w)

    def encrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) -> InlineArray[UInt8, BLOCK_SIZE]:
        return cpu_cipher[Nr=Self.Nr](block, self.w)

    def decrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) -> InlineArray[UInt8, BLOCK_SIZE]:
        return cpu_decipher[Nr=Self.Nr](block, self.w)

    def encrypt_block[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        var result = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
        var block_in = ctx.enqueue_create_buffer[DType.uint8](BLOCK_SIZE)
        block_in.enqueue_copy_from(block)

        comptime kernel = gpu_cipher[Self.Nr]
        if not self._gpu:
            raise Error(
                "GPU context not initialized; construct Aes with a"
                " DeviceContext to use GPU methods"
            )
        ctx.enqueue_function[kernel, kernel](
            block_in,
            self._gpu.value().w_dev,
            self._gpu.value().sbox_dev,
            grid_dim=BLOCKS_PER_GRID,
            block_dim=BLOCK_SIZE,
        )
        block_in.enqueue_copy_to(result.unsafe_ptr())
        return result

    def decrypt_block[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        var result = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
        var block_in = ctx.enqueue_create_buffer[DType.uint8](BLOCK_SIZE)
        block_in.enqueue_copy_from(block)

        comptime kernel = gpu_decipher[Self.Nr]
        if not self._gpu:
            raise Error(
                "GPU context not initialized; construct Aes with a"
                " DeviceContext to use GPU methods"
            )
        ctx.enqueue_function[kernel, kernel](
            block_in,
            self._gpu.value().w_dev,
            self._gpu.value().sbox_inv_dev,
            grid_dim=BLOCKS_PER_GRID,
            block_dim=BLOCK_SIZE,
        )
        block_in.enqueue_copy_to(result.unsafe_ptr())
        return result


struct AesGpuSetup(ImplicitlyDestructible, Movable):
    var w_dev: DeviceBuffer[DType.uint32]
    var sbox_dev: DeviceBuffer[DType.uint32]
    var sbox_inv_dev: DeviceBuffer[DType.uint8]

    def __init__[
        WordsSize: Int
    ](out self, ctx: DeviceContext, w: InlineArray[UInt32, WordsSize]) raises:
        var w_dev = ctx.enqueue_create_buffer[DType.uint32](WordsSize)
        w_dev.enqueue_copy_from(w)
        self.w_dev = w_dev^

        var sbox_dev = ctx.enqueue_create_buffer[DType.uint32](256)
        sbox_dev.enqueue_copy_from(SBOX.unsafe_ptr())
        self.sbox_dev = sbox_dev^

        var sbox_inv_dev = ctx.enqueue_create_buffer[DType.uint8](256)
        sbox_inv_dev.enqueue_copy_from(SBOX_INV.unsafe_ptr())
        self.sbox_inv_dev = sbox_inv_dev^
