from std.sys.info import CompilationTarget
from warp import Context


trait BlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


trait BlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


trait GpuBlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    __async def encrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        ...


trait GpuBlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    __async def decrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        ...
