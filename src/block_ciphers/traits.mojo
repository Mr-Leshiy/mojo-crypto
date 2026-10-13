from warp import Context


trait BlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


trait BlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        ...


# Async counterparts for device-backed ciphers, run as coroutines on a warp
# `Executor`. `ctx` hands out the executor's `DeviceContext`, and awaiting
# `ctx.synchronize()` yields to the other queued tasks instead of blocking.
# `self` is immutable, so several tasks can share one cipher.
trait AsyncBlockCipherEncryptable:
    comptime BLOCK_SIZE: Int

    __async def encrypt[
        o: MutOrigin
    ](self, ctx: Context, data: Span[UInt8, o]) raises:
        ...


trait AsyncBlockCipherDecryptable:
    comptime BLOCK_SIZE: Int

    __async def decrypt[
        o: MutOrigin
    ](self, ctx: Context, data: Span[UInt8, o]) raises:
        ...
