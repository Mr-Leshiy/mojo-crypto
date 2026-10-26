from std.sys import has_accelerator
from max.gpu.host import DeviceContext
from warp import Runtime

from mojo_crypto.utils import target_triple_contains_any, has_target_feature
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

# Which AES backends the current build can run. A test suite registers the
# tests of a backend only when its flag is set: the hardware backends are
# compiled in only for their target, and without an accelerator the GPU
# kernels cannot even be compiled.
comptime HAS_AES_AARCH64 = target_triple_contains_any(
    ["aarch64", "arm64"]
) and has_target_feature["aes"]()
comptime HAS_AES_X86 = target_triple_contains_any(
    ["x86_64"]
) and has_target_feature["aes"]()
comptime HAS_AES_GPU = has_accelerator()


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


def run_aes_checks[
    TestInput: Copyable,
    check: def[
        C: BlockCipherEngine,
        KeySize: Int,
        //,
        cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
    ](TestInput) raises capturing[_],
](input: TestInput) raises:
    comptime if HAS_AES_AARCH64:

        @__parameter
        def aes_aarch64[
            KeySize: Int
        ](key: Array[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
            return AesAarch64[KeySize](key)

        check[aes_aarch64[16]](input)
        check[aes_aarch64[24]](input)
        check[aes_aarch64[32]](input)

    comptime if HAS_AES_X86:

        @__parameter
        def aes_x86[
            KeySize: Int
        ](key: Array[UInt8, KeySize]) raises -> AesX86[KeySize]:
            return AesX86[KeySize](key)

        check[aes_x86[16]](input)
        check[aes_x86[24]](input)
        check[aes_x86[32]](input)

    @__parameter
    def aes_cpu[
        KeySize: Int
    ](key: Array[UInt8, KeySize]) raises -> AesNaive[KeySize]:
        return AesNaive[KeySize](key)

    check[aes_cpu[16]](input)
    check[aes_cpu[24]](input)
    check[aes_cpu[32]](input)

    # Compile-time guard: without an accelerator the GPU kernels cannot even
    # be compiled, so skipping at runtime is not enough.
    comptime if HAS_AES_GPU:
        with DeviceContext() as ctx:
            var runtime = Runtime(ctx)

            @__parameter
            def aes_gpu[
                KeySize: Int
            ](key: Array[UInt8, KeySize]) raises -> BlockOn[AesGpu[KeySize]]:
                var cipher = runtime.block_on(
                    AesGpu[KeySize].create(runtime.context(), key)
                )
                return BlockOn(runtime, cipher^)

            check[aes_gpu[16]](input)
            check[aes_gpu[24]](input)
            check[aes_gpu[32]](input)
