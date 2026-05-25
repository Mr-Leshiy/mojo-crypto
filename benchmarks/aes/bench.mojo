from std.benchmark import run
from std.gpu.host import DeviceContext

from mojo_crypto.aes import Aes, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

# Shared block counts — CPU loops this many times, GPU launches this many blocks.
# Same total work, different parallelism — makes CPU vs GPU comparison meaningful.
comptime BLOCKS_256: Int = 256
comptime BLOCKS_1K: Int = 1_024
comptime BLOCKS_4K: Int = 4_096
comptime BLOCKS_8K: Int = 8_192
comptime BLOCKS_16K: Int = 16_384


def bench_cpu_cipher[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    label: StringLiteral,
]() raises:
    var key = InlineArray[UInt8, KeySize](fill=0)
    var cipher = cipher_init(key)
    var prefix = String(label) + "_cpu"

    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var data = InlineArray[UInt8, N](fill=0)

        @parameter
        def do_encrypt() raises:
            cipher.encrypt(data)

        @parameter
        def do_decrypt() raises:
            cipher.decrypt(data)

        run[do_encrypt]().print(prefix + "_encrypt_" + suffix)
        run[do_decrypt]().print(prefix + "_decrypt_" + suffix)

    bench[BLOCKS_4K, "4kb"]()
    bench[BLOCKS_8K, "8kb"]()
    bench[BLOCKS_16K, "16kb"]()


def bench_gpu_cipher[
    C: GpuBlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    label: StringLiteral,
](ctx: DeviceContext) raises:
    var key = InlineArray[UInt8, KeySize](fill=0)
    var cipher = cipher_init(key)
    var prefix = String(label) + "_gpu"

    @parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var data = InlineArray[UInt8, N](fill=0)

        @parameter
        def do_encrypt() raises:
            cipher.encrypt(ctx, data)
            ctx.synchronize()

        @parameter
        def do_decrypt() raises:
            cipher.decrypt(ctx, data)
            ctx.synchronize()

        run[do_encrypt]().print(prefix + "_encrypt_" + suffix)
        run[do_decrypt]().print(prefix + "_decrypt_" + suffix)

    bench[BLOCKS_4K, "4kb"]()
    bench[BLOCKS_8K, "8kb"]()
    bench[BLOCKS_16K, "16kb"]()


def main() raises:
    print("Running aes benches")
    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key)

        @parameter
        def aes_gpu[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key, ctx)

        bench_cpu_cipher[Aes[16], 16, aes[16], "aes128"]()
        # bench_cpu_cipher[Aes[24], 24, aes[24], "aes192"]()
        # bench_cpu_cipher[Aes[32], 32, aes[32], "aes256"]()

        bench_gpu_cipher[Aes[16], 16, aes_gpu[16], "aes128"](ctx)
        # bench_gpu_cipher[Aes[24], 24, aes_gpu[24], "aes192"](ctx)
        # bench_gpu_cipher[Aes[32], 32, aes_gpu[32], "aes256"](ctx)
