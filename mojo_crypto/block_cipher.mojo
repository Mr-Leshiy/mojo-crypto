from std.gpu.host import DeviceContext

from .aes.common import BLOCK_SIZE
from .errors import GpuContextError


trait BlockCipher:
    def encrypt[Size: Int](self, mut data: InlineArray[UInt8, Size]) raises:
        ...

    def decrypt[Size: Int](self, mut data: InlineArray[UInt8, Size]) raises:
        ...


trait GpuBlockCipher(ImplicitlyDestructible):
    def encrypt[
        Size: Int
    ](self, ctx: DeviceContext, mut data: InlineArray[UInt8, Size]) raises:
        ...

    def decrypt[
        Size: Int
    ](self, ctx: DeviceContext, mut data: InlineArray[UInt8, Size]) raises:
        ...
