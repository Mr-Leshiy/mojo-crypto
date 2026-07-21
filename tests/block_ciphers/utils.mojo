from std.sys import has_accelerator
from std.gpu.host import DeviceContext

from mojo_crypto.utils import target_triple_contains_any
from mojo_crypto.block_ciphers.aes import (
    AesCpu,
    AesAarch64,
    AesX86,
    AesGpu,
)
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)


def run_aes_checks[
    TestVector: Copyable & Movable,
    check: def[
        C: BlockCipherEncryptable
        & BlockCipherDecryptable
        & Copyable
        & Movable
        & ImplicitlyDestructible,
        KeySize: Int,
        cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    ](List[TestVector]) raises capturing[_],
](vectors: List[TestVector]) raises:
    comptime if has_accelerator():
        with DeviceContext() as ctx:

            @parameter
            def aes_gpu[
                KeySize: Int
            ](key: InlineArray[UInt8, KeySize]) raises -> AesGpu[KeySize]:
                return AesGpu[KeySize](ctx, key)

            check[AesGpu[16], 16, aes_gpu[16]](vectors)
            check[AesGpu[24], 24, aes_gpu[24]](vectors)
            check[AesGpu[32], 32, aes_gpu[32]](vectors)

    comptime if target_triple_contains_any(["aarch64", "arm64"]):

        @parameter
        def aes_aarch64[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesAarch64[KeySize]:
            return AesAarch64[KeySize](key)

        check[AesAarch64[16], 16, aes_aarch64[16]](vectors)
        check[AesAarch64[24], 24, aes_aarch64[24]](vectors)
        check[AesAarch64[32], 32, aes_aarch64[32]](vectors)

    comptime if target_triple_contains_any(["x86_64"]):

        @parameter
        def aes_x86[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> AesX86[KeySize]:
            return AesX86[KeySize](key)

        check[AesX86[16], 16, aes_x86[16]](vectors)
        check[AesX86[24], 24, aes_x86[24]](vectors)
        check[AesX86[32], 32, aes_x86[32]](vectors)

    @parameter
    def aes_cpu[
        KeySize: Int
    ](key: InlineArray[UInt8, KeySize]) raises -> AesCpu[KeySize]:
        return AesCpu[KeySize](key)

    check[AesCpu[16], 16, aes_cpu[16]](vectors)
    check[AesCpu[24], 24, aes_cpu[24]](vectors)
    check[AesCpu[32], 32, aes_cpu[32]](vectors)
