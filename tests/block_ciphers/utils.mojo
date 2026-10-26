from warp import Runtime

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
