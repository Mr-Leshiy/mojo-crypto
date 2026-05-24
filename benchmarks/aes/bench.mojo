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
    def bench_encrypt[N: Int]() raises:
        var data = InlineArray[UInt8, N](fill=0)
        cipher.encrypt(data)

    @parameter
    def bench_decrypt[N: Int]() raises:
        var data = InlineArray[UInt8, N](fill=0)
        cipher.decrypt(data)

    run[bench_encrypt[BLOCKS_256]]().print(prefix + "_encrypt_256b")
    run[bench_decrypt[BLOCKS_256]]().print(prefix + "_decrypt_256b")

    run[bench_encrypt[BLOCKS_1K]]().print(prefix + "_encrypt_1kb")
    run[bench_decrypt[BLOCKS_1K]]().print(prefix + "_decrypt_1kb")

    run[bench_encrypt[BLOCKS_4K]]().print(prefix + "_encrypt_4kb")
    run[bench_decrypt[BLOCKS_4K]]().print(prefix + "_decrypt_4kb")

    run[bench_encrypt[BLOCKS_8K]]().print(prefix + "_encrypt_8kb")
    run[bench_decrypt[BLOCKS_8K]]().print(prefix + "_decrypt_8kb")

    run[bench_encrypt[BLOCKS_16K]]().print(prefix + "_encrypt_16kb")
    run[bench_decrypt[BLOCKS_16K]]().print(prefix + "_decrypt_16kb")


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
    def bench_encrypt[N: Int]() raises:
        var data = InlineArray[UInt8, N](fill=0)
        cipher.encrypt(ctx, data)
        ctx.synchronize()

    @parameter
    def bench_decrypt[N: Int]() raises:
        var data = InlineArray[UInt8, N](fill=0)
        cipher.decrypt(ctx, data)
        ctx.synchronize()

    run[bench_encrypt[BLOCKS_256]]().print(prefix + "_encrypt_256b")
    run[bench_decrypt[BLOCKS_256]]().print(prefix + "_decrypt_256b")

    run[bench_encrypt[BLOCKS_1K]]().print(prefix + "_encrypt_1kb")
    run[bench_decrypt[BLOCKS_1K]]().print(prefix + "_decrypt_1kb")

    run[bench_encrypt[BLOCKS_4K]]().print(prefix + "_encrypt_4kb")
    run[bench_decrypt[BLOCKS_4K]]().print(prefix + "_decrypt_4kb")

    run[bench_encrypt[BLOCKS_8K]]().print(prefix + "_encrypt_8kb")
    run[bench_decrypt[BLOCKS_8K]]().print(prefix + "_decrypt_8kb")

    run[bench_encrypt[BLOCKS_16K]]().print(prefix + "_encrypt_16kb")
    run[bench_decrypt[BLOCKS_16K]]().print(prefix + "_decrypt_16kb")


def main() raises:
    print("Running aes benches")
    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key, ctx)

        # bench_cpu_cipher[Aes[16], 16, aes[16], "aes128"]()
        # bench_cpu_cipher[Aes[24], 24, aes[24], "aes192"]()
        # bench_cpu_cipher[Aes[32], 32, aes[32], "aes256"]()

        bench_gpu_cipher[Aes[16], 16, aes[16], "aes128"](ctx)
        # bench_gpu_cipher[Aes[24], 24, aes[24], "aes192"](ctx)
        # bench_gpu_cipher[Aes[32], 32, aes[32], "aes256"](ctx)
