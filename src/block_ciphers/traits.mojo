from warp import Context


trait BlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


trait BlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


trait AsyncBlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    __async def encrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        ...


trait AsyncBlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    __async def decrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        ...
