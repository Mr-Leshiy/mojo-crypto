from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    AesAarch64,
    AesX86,
    AesGpu,
)
from mojo_crypto.block_ciphers.modes import CtrMode, GpuCtrMode
from mojo_crypto.block_ciphers.traits import (
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)

from tests.platform import HAS_GPU

comptime BlockCipherEngine = (
    BlockCipherEncryptable & BlockCipherDecryptable & Copyable & Deinitable
)

comptime AsyncBlockCipherEngine = (
    AsyncBlockCipherEncryptable
    & AsyncBlockCipherDecryptable
    & Copyable
    & Deinitable
)


comptime BlockCipherModeEngine = (
    BlockCipherEncryptable & BlockCipherDecryptable & Movable & Deinitable
)


trait AesFactory(Deinitable, Movable):
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


trait CtrFactory:
    """Creates the CTR modes of one backend, key size and counter layout, so
    that a check can be written once and run against every backend."""

    comptime KEY_SIZE: Int
    comptime BLOCK_SIZE: Int
    comptime Mode: BlockCipherModeEngine

    def create(
        self,
        key: Array[UInt8, Self.KEY_SIZE],
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ) raises -> Self.Mode:
        ...


@fieldwise_init
struct CtrModeFactory[
    F: AesFactory,
    //,
    SIZE: Int = F.Cipher.BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](CtrFactory):
    """Creates `CtrMode`s over the ciphers of a sync AES backend."""

    comptime KEY_SIZE: Int = Self.F.KEY_SIZE
    comptime BLOCK_SIZE: Int = Self.F.Cipher.BLOCK_SIZE
    comptime Mode = CtrMode[Self.F.Cipher, Self.SIZE, Self.BIG_ENDIAN]

    var _aes: Self.F

    def create(
        self,
        key: Array[UInt8, Self.KEY_SIZE],
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ) raises -> Self.Mode:
        return Self.Mode(self._aes.create(key), ctr^)


struct GpuCtrModeFactory[
    KeySize: Int,
    SIZE: Int = AesGpu[KeySize].BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](CtrFactory):
    """Creates `GpuCtrMode`s on the given device, each wrapped in `BlockOn` so
    that the sync checks can run against it."""

    comptime KEY_SIZE: Int = Self.KeySize
    comptime BLOCK_SIZE: Int = AesGpu[Self.KeySize].BLOCK_SIZE
    comptime Mode = BlockOn[
        GpuCtrMode[AesGpu[Self.KeySize], Self.SIZE, Self.BIG_ENDIAN]
    ]

    var _runtime: Runtime

    def __init__(out self, ctx: DeviceContext):
        self._runtime = Runtime(ctx)

    def create(
        self,
        key: Array[UInt8, Self.KEY_SIZE],
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ) raises -> Self.Mode:
        var runtime = self._runtime.copy()
        var cipher = runtime.block_on(
            AesGpu[Self.KeySize].create(runtime.context(), key)
        )
        return BlockOn(
            runtime,
            GpuCtrMode[AesGpu[Self.KeySize], Self.SIZE, Self.BIG_ENDIAN](
                cipher^, ctr^
            ),
        )


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
    checks can run against it.

    Without an accelerator the engine's GPU kernels cannot even be compiled, so
    every call raises instead. This keeps GPU tests compilable on any build;
    they are only registered when an accelerator is present.
    """

    comptime BLOCK_SIZE: Int = Self.Engine.BLOCK_SIZE

    var _runtime: Runtime
    var _engine: Self.Engine

    def __init__(out self, runtime: Runtime, var engine: Self.Engine):
        self._runtime = runtime.copy()
        self._engine = engine^

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if HAS_GPU:
            var ctx = self._runtime.context()
            self._runtime.block_on(self._engine.encrypt(ctx, data))
        else:
            raise Error("BlockOn.encrypt: no accelerator in this build")

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if HAS_GPU:
            var ctx = self._runtime.context()
            self._runtime.block_on(self._engine.decrypt(ctx, data))
        else:
            raise Error("BlockOn.decrypt: no accelerator in this build")
