from std.benchmark import run
from std.gpu.host import DeviceContext

from mojo_crypto.aes import Aes, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

# Shared block counts — CPU loops this many times, GPU launches this many blocks.
# Same total work, different parallelism — makes CPU vs GPU comparison meaningful.
comptime BLOCKS_256: Int = 256
comptime BLOCKS_1K: Int = 1024
comptime BLOCKS_4K: Int = 4096


def bench_cpu_cipher[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    label: StringLiteral,
](key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label) + "_cpu"

    @parameter
    def bench_encrypt_256blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(BLOCKS_256):
            block = cipher.encrypt(block)

    @parameter
    def bench_encrypt_1kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(BLOCKS_1K):
            block = cipher.encrypt(block)

    @parameter
    def bench_encrypt_4kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(BLOCKS_4K):
            block = cipher.encrypt(block)

    @parameter
    def bench_decrypt_256blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(BLOCKS_256):
            block = cipher.decrypt(block)

    @parameter
    def bench_decrypt_1kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(BLOCKS_1K):
            block = cipher.decrypt(block)

    @parameter
    def bench_decrypt_4kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(BLOCKS_4K):
            block = cipher.decrypt(block)

    print(prefix + "_encrypt_256blk")
    run[bench_encrypt_256blk]().print()
    print(prefix + "_encrypt_1kblk")
    run[bench_encrypt_1kblk]().print()
    print(prefix + "_encrypt_4kblk")
    run[bench_encrypt_4kblk]().print()
    print(prefix + "_decrypt_256blk")
    run[bench_decrypt_256blk]().print()
    print(prefix + "_decrypt_1kblk")
    run[bench_decrypt_1kblk]().print()
    print(prefix + "_decrypt_4kblk")
    run[bench_decrypt_4kblk]().print()


def bench_gpu_cipher[
    C: BlockCipher & GpuBlockCipher,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    label: StringLiteral,
](ctx: DeviceContext, key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label) + "_gpu"

    @parameter
    def bench_encrypt_256blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[BLOCKS_256](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_encrypt_1kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[BLOCKS_1K](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_encrypt_4kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[BLOCKS_4K](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_256blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[BLOCKS_256](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_1kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[BLOCKS_1K](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_4kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[BLOCKS_4K](ctx, block)
        ctx.synchronize()

    print(prefix + "_encrypt_256blk")
    run[bench_encrypt_256blk]().print()
    print(prefix + "_encrypt_1kblk")
    run[bench_encrypt_1kblk]().print()
    print(prefix + "_encrypt_4kblk")
    run[bench_encrypt_4kblk]().print()
    print(prefix + "_decrypt_256blk")
    run[bench_decrypt_256blk]().print()
    print(prefix + "_decrypt_1kblk")
    run[bench_decrypt_1kblk]().print()
    print(prefix + "_decrypt_4kblk")
    run[bench_decrypt_4kblk]().print()


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
