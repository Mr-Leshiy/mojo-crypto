from std.gpu.host import DeviceContext

from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

from .cpu.cipher import cipher as cpu_cipher, decipher as cpu_decipher
from .gpu.cipher import cipher as gpu_cipher, decipher as gpu_decipher
from .expand import key_expansion
from .common import Nb, BLOCK_SIZE, SBOX, SBOX_INV


# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
struct Aes[KeySize: Int](BlockCipher, GpuBlockCipher):
    comptime Nk: Int = Self.KeySize // 4
    comptime Nr: Int = Self.Nk + 6
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var w: InlineArray[UInt32, Self.WordsSize]

    def __init__(out self, key: InlineArray[UInt8, Self.KeySize]):
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"

        self.w = key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)

    def encrypt(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) -> InlineArray[UInt8, BLOCK_SIZE]:
        return cpu_cipher[Nr=Self.Nr](block, self.w)

    def decrypt(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) -> InlineArray[UInt8, BLOCK_SIZE]:
        return cpu_decipher[Nr=Self.Nr](block, self.w)

    def encrypt[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        var result = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)

        var block_in = ctx.enqueue_create_buffer[DType.uint8](BLOCK_SIZE)
        block_in.enqueue_copy_from(block)
        var w = ctx.enqueue_create_buffer[DType.uint32](Self.WordsSize)
        w.enqueue_copy_from(self.w)
        var sbox = ctx.enqueue_create_buffer[DType.uint32](256)
        sbox.enqueue_copy_from(SBOX.unsafe_ptr())

        comptime kernel = gpu_cipher[Self.Nr]
        ctx.enqueue_function[kernel, kernel](
            block_in,
            w,
            sbox,
            grid_dim=BLOCKS_PER_GRID,
            block_dim=BLOCK_SIZE,
        )
        block_in.enqueue_copy_to(result.unsafe_ptr())

        return result

    def decrypt[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        var result = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)

        var block_in = ctx.enqueue_create_buffer[DType.uint8](BLOCK_SIZE)
        block_in.enqueue_copy_from(block)
        var w = ctx.enqueue_create_buffer[DType.uint32](Self.WordsSize)
        w.enqueue_copy_from(self.w)
        var sbox_inv = ctx.enqueue_create_buffer[DType.uint8](256)
        sbox_inv.enqueue_copy_from(SBOX_INV.unsafe_ptr())

        comptime kernel = gpu_decipher[Self.Nr]
        ctx.enqueue_function[kernel, kernel](
            block_in,
            w,
            sbox_inv,
            grid_dim=BLOCKS_PER_GRID,
            block_dim=BLOCK_SIZE,
        )
        block_in.enqueue_copy_to(result.unsafe_ptr())

        return result
