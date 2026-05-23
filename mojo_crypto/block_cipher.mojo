from std.gpu.host import DeviceContext

from .aes.common import BLOCK_SIZE


trait BlockCipher:
    def encrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def decrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...


trait GpuBlockCipher(ImplicitlyDestructible):
    def encrypt_block[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def decrypt_block[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...
