from std.sys import has_accelerator
from std.gpu.host import DeviceContext

from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.block_ciphers.aes import (
    AesNaive,
    AesAarch64,
    AesX86,
    AesGpu,
)
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)

comptime BlockCipherEngine = (
    BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & ImplicitlyDeletable
)


def run_aes_checks[
    TestInput: Copyable,
    check: def[
        C: BlockCipherEngine,
        KeySize: Int,
        //,
        cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    ](TestInput) raises capturing[_],
](input: TestInput) raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:

            @parameter
            def aes_gpu[
                KeySize: Int
            ](key: InlineArray[UInt8, KeySize]) raises -> AesGpu[KeySize]:
                return AesGpu[KeySize](ctx, key)

            check[aes_gpu[16]](input)
            check[aes_gpu[24]](input)
            check[aes_gpu[32]](input)

    comptime if target_triple_contains_any(["aarch64", "arm64"]):

        @parameter
        def aes_aarch64[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
            return AesAarch64[KeySize](key)

        check[aes_aarch64[16]](input)
        check[aes_aarch64[24]](input)
        check[aes_aarch64[32]](input)

    comptime if target_triple_contains_any(["x86_64"]):

        @parameter
        def aes_x86[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesX86[KeySize]:
            return AesX86[KeySize](key)

        check[aes_x86[16]](input)
        check[aes_x86[24]](input)
        check[aes_x86[32]](input)

    @parameter
    def aes_cpu[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesNaive[KeySize]:
        return AesNaive[KeySize](key)

    check[aes_cpu[16]](input)
    check[aes_cpu[24]](input)
    check[aes_cpu[32]](input)
