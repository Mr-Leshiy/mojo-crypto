from std.benchmark import run
from std.gpu.host import DeviceContext

from mojo_crypto.aes import Aes, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

# Shared block counts — CPU loops this many times, GPU launches this many blocks.
# Same total work, different parallelism — makes CPU vs GPU comparison meaningful.
comptime BLOCKS_256: Int = 256
comptime BLOCKS_1K: Int = 1024
comptime BLOCKS_4K: Int = 4096


def run_bench[f: def() raises capturing[_]](name: String) raises:
    print(name)
    run[f]().print()


def bench_cpu_cipher[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    label: StringLiteral,
](key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label) + "_cpu"

    @parameter
    def bench_encrypt[N: Int]() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(N):
            block = cipher.encrypt_block(block)

    @parameter
    def bench_decrypt[N: Int]() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(N):
            block = cipher.decrypt_block(block)

    run_bench[bench_encrypt[BLOCKS_256]](prefix + "_encrypt_256blk")
    run_bench[bench_encrypt[BLOCKS_1K]](prefix + "_encrypt_1kblk")
    run_bench[bench_encrypt[BLOCKS_4K]](prefix + "_encrypt_4kblk")
    run_bench[bench_decrypt[BLOCKS_256]](prefix + "_decrypt_256blk")
    run_bench[bench_decrypt[BLOCKS_1K]](prefix + "_decrypt_1kblk")
    run_bench[bench_decrypt[BLOCKS_4K]](prefix + "_decrypt_4kblk")


def bench_gpu_cipher[
    C: BlockCipher & GpuBlockCipher,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    label: StringLiteral,
](ctx: DeviceContext, key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label) + "_gpu"

    @parameter
    def bench_encrypt[N: Int]() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(N):
            block = cipher.encrypt_block(ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt[N: Int]() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(N):
            block = cipher.decrypt_block(ctx, block)
        ctx.synchronize()

    run_bench[bench_encrypt[BLOCKS_256]](prefix + "_encrypt_256blk")
    run_bench[bench_encrypt[BLOCKS_1K]](prefix + "_encrypt_1kblk")
    run_bench[bench_encrypt[BLOCKS_4K]](prefix + "_encrypt_4kblk")
    run_bench[bench_decrypt[BLOCKS_256]](prefix + "_decrypt_256blk")
    run_bench[bench_decrypt[BLOCKS_1K]](prefix + "_decrypt_1kblk")
    run_bench[bench_decrypt[BLOCKS_4K]](prefix + "_decrypt_4kblk")


def main() raises:
    with DeviceContext() as ctx:

        @parameter
        def aes[
            KeySize: Int
        ](key: InlineArray[UInt8, KeySize]) raises -> Aes[KeySize]:
            return Aes[KeySize](key, ctx)

        bench_cpu_cipher[Aes[16], 16, aes[16], "aes128"](
            InlineArray[UInt8, 16](fill=0)
        )
        # bench_cpu_cipher[Aes[24], 24, aes[24], "aes192"](InlineArray[UInt8, 24](fill=0))
        # bench_cpu_cipher[Aes[32], 32, aes[32], "aes256"](InlineArray[UInt8, 32](fill=0))

        bench_gpu_cipher[Aes[16], 16, aes[16], "aes128"](
            ctx, InlineArray[UInt8, 16](fill=0)
        )
        # bench_gpu_cipher[Aes[24], 24, aes_gpu[24], "aes192"](ctx, InlineArray[UInt8, 24](fill=0))
        # bench_gpu_cipher[Aes[32], 32, aes_gpu[32], "aes256"](ctx, InlineArray[UInt8, 32](fill=0))
