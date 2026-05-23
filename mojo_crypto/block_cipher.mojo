from std.gpu.host import DeviceContext

from .aes.common import BLOCK_SIZE
from .errors import GpuContextError


trait BlockCipher:
    def encrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def decrypt_block(
        self, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def encrypt[
        Size: Int
    ](self, data: InlineArray[UInt8, Size]) raises -> InlineArray[UInt8, Size]:
        ...

    def decrypt[
        Size: Int
    ](self, data: InlineArray[UInt8, Size]) raises -> InlineArray[UInt8, Size]:
        ...


trait GpuBlockCipher(ImplicitlyDestructible):
    def encrypt_block(
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def decrypt_block(
        self, ctx: DeviceContext, block: InlineArray[UInt8, BLOCK_SIZE]
    ) raises -> InlineArray[UInt8, BLOCK_SIZE]:
        ...

    def encrypt[
        Size: Int
    ](
        self, ctx: DeviceContext, data: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        ...

    def decrypt[
        Size: Int
    ](
        self, ctx: DeviceContext, data: InlineArray[UInt8, Size]
    ) raises -> InlineArray[UInt8, Size]:
        ...
