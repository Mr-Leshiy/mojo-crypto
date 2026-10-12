from std.sys import has_accelerator
from max.gpu.host import DeviceContext
from warp import Executor

from mojo_crypto.utils import target_triple_contains_any, has_target_feature
from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    AesAarch64,
    AesX86,
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


def run_async_aes_checks[
    TestInput: Copyable,
    check: def[
        C: AsyncBlockCipherEngine,
        KeySize: Int,
        //,
        cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
    ](mut Executor, TestInput) raises capturing[_],
](input: TestInput) raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:
            var executor = Executor(ctx)
            # TODO: run `check` against `AesGpu` once it implements the async
            # traits.
            _ = executor^


def encrypt_async[
    C: AsyncBlockCipherEncryptable, o: MutOrigin
](mut executor: Executor, cipher: C, data: Span[UInt8, o]) raises:
    var task = executor.add(cipher.encrypt(executor.context(), data))
    task^.wait()


def decrypt_async[
    C: AsyncBlockCipherDecryptable, o: MutOrigin
](mut executor: Executor, cipher: C, data: Span[UInt8, o]) raises:
    var task = executor.add(cipher.decrypt(executor.context(), data))
    task^.wait()
