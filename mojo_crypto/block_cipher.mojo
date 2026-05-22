from std.gpu.host import DeviceContext

from .aes.common import BLOCK_SIZE


trait BlockCipher:
    def encrypt(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def decrypt(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...


trait GpuBlockCipher(ImplicitlyDestructible):
    def encrypt[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def decrypt[
        BLOCKS_PER_GRID: Int
    ](
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...
