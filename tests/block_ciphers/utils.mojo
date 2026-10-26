from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    AesAarch64,
    AesX86,
    AesGpu,
)
from mojo_crypto.block_ciphers.traits import (
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)

comptime BlockCipherEngine = (
    BlockCipherEncryptable & BlockCipherDecryptable & Copyable & Deinitable
)

comptime AsyncBlockCipherEngine = (
    AsyncBlockCipherEncryptable
    & AsyncBlockCipherDecryptable
    & Copyable
    & Deinitable
)


trait AesFactory:
    """Creates the AES ciphers of one backend and key size, so that a check
    can be written once and run against every backend."""

    comptime KEY_SIZE: Int
    comptime Cipher: BlockCipherEngine

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        ...


@fieldwise_init
struct AesNaiveFactory[KeySize: Int](AesFactory):
    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = AesNaive[Self.KeySize]

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        return Self.Cipher(key)


@fieldwise_init
struct AesAarch64Factory[KeySize: Int](AesFactory):
    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = AesAarch64[Self.KeySize]

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        return Self.Cipher(key)


@fieldwise_init
struct AesX86Factory[KeySize: Int](AesFactory):
    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = AesX86[Self.KeySize]

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        return Self.Cipher(key)


struct AesGpuFactory[KeySize: Int](AesFactory):
    """Creates GPU ciphers on the given device, each wrapped in `BlockOn` so
    that the sync checks can run against it."""

    comptime KEY_SIZE: Int = Self.KeySize
    comptime Cipher = BlockOn[AesGpu[Self.KeySize]]

    var _runtime: Runtime

    def __init__(out self, ctx: DeviceContext):
        self._runtime = Runtime(ctx)

    def create(self, key: Array[UInt8, Self.KEY_SIZE]) raises -> Self.Cipher:
        var runtime = self._runtime.copy()
        var cipher = runtime.block_on(
            AesGpu[Self.KeySize].create(runtime.context(), key)
        )
        return BlockOn(runtime, cipher^)


struct BlockOn[
    Engine: AsyncBlockCipherEncryptable
    & AsyncBlockCipherDecryptable
    & Movable
    & Deinitable
](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Copyable where conforms_to(Engine, Copyable),
    Deinitable,
    Movable,
):
    """Drives an async engine to completion on every call, so that the sync
    checks can run against it."""

    comptime BLOCK_SIZE: Int = Self.Engine.BLOCK_SIZE

    var _runtime: Runtime
    var _engine: Self.Engine

    def __init__(out self, runtime: Runtime, var engine: Self.Engine):
        self._runtime = runtime.copy()
        self._engine = engine^

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        var ctx = self._runtime.context()
        self._runtime.block_on(self._engine.encrypt(ctx, data))

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        var ctx = self._runtime.context()
        self._runtime.block_on(self._engine.decrypt(ctx, data))
