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
    comptime if target_triple_contains_any(
        ["aarch64", "arm64"]
    ) and has_target_feature["aes"]():

        @__parameter
        def aes_aarch64[
            KeySize: Int
        ](key: Array[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
            return AesAarch64[KeySize](key)

        check[aes_aarch64[16]](input)
        check[aes_aarch64[24]](input)
        check[aes_aarch64[32]](input)

    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "aes"
    ]():

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
    comptime if has_accelerator():
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
