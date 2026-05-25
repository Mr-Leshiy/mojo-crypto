from std.gpu.host import DeviceContext

from .aes.common import BLOCK_SIZE
from .errors import GpuContextError


trait BlockCipher:
    def encrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        ...

    def decrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        ...


trait GpuBlockCipher:
    def encrypt[
        o: MutOrigin
    ](self, ctx: DeviceContext, data: Span[UInt8, o]) raises:
        ...

    def decrypt[
        o: MutOrigin
    ](self, ctx: DeviceContext, data: Span[UInt8, o]) raises:
        ...
