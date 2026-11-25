from max.gpu.host import DeviceBuffer
from std.sys.info import CompilationTarget
from warp import Context


trait BlockCipherEncryptable:
    """Encryption with a block cipher or a mode over one."""

    comptime BLOCK_SIZE: Int
    """Size of the cipher's block, in bytes."""

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        """Encrypt `data` in place."""
        ...


trait BlockCipherDecryptable:
    """Decryption with a block cipher or a mode over one."""

    comptime BLOCK_SIZE: Int
    """Size of the cipher's block, in bytes."""

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        """Decrypt `data` in place."""
        ...


trait GpuBlockCipherEncryptable:
    """Encryption with a block cipher, or a mode over one, on a GPU."""

    comptime BLOCK_SIZE: Int
    """Size of the cipher's block, in bytes."""

    __async def encrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        """Encrypt host `data` in place, returning once fully synchronized."""
        ...

    def encrypt[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        """Enqueue in-place encryption of device `data`.

        Synchronizing `ctx` is the caller's responsibility.
        """
        ...


trait GpuBlockCipherDecryptable:
    """Decryption with a block cipher, or a mode over one, on a GPU."""

    comptime BLOCK_SIZE: Int
    """Size of the cipher's block, in bytes."""

    __async def decrypt[
        target: CompilationTarget, o: MutOrigin
    ](mut self, ctx: Context[target], data: Span[UInt8, o]) raises:
        """Decrypt host `data` in place, returning once fully synchronized."""
        ...

    def decrypt[
        target: CompilationTarget
    ](mut self, ctx: Context[target], data: DeviceBuffer[DType.uint8]) raises:
        """Enqueue in-place decryption of device `data`.

        Synchronizing `ctx` is the caller's responsibility.
        """
        ...
