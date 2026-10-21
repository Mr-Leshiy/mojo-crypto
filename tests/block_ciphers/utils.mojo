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


def run_gpu_aes_checks[
    TestInput: Copyable,
    check: def[
        C: AsyncBlockCipherEngine,
        KeySize: Int,
        //,
        cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
    ](mut Runtime, TestInput) raises capturing[_],
](input: TestInput) raises:
    with DeviceContext() as ctx:
        var runtime = Runtime(ctx)

        @__parameter
        def aes_gpu[
            KeySize: Int
        ](key: Array[UInt8, KeySize]) raises -> AesGpu[KeySize]:
            return runtime.block_on(
                AesGpu[KeySize].create(runtime.context(), key)
            )

        check[aes_gpu[16]](runtime, input)
        check[aes_gpu[24]](runtime, input)
        check[aes_gpu[32]](runtime, input)
