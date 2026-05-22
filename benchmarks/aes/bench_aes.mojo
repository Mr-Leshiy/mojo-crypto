from std.benchmark import run
from std.gpu.host import DeviceContext

from mojo_crypto.aes import Aes, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

# CPU: sequential block chain depth
comptime NBLOCKS: Int = 1024

# GPU: grid sizes — increasing these is how you saturate the GPU, not looping calls
comptime GPU_BLOCKS_1: Int = 1  # baseline: launch overhead only
comptime GPU_BLOCKS_256: Int = 256  # light load
comptime GPU_BLOCKS_1K: Int = 1024  # moderate load
comptime GPU_BLOCKS_4K: Int = 4096  # heavy load


@parameter
def aes[KeySize: Int](key: InlineArray[UInt8, KeySize]) -> Aes[KeySize]:
    return Aes[KeySize](key)


def bench_cpu_cipher[
    C: BlockCipher,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) capturing[_] -> C,
    label: StringLiteral,
](key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label) + "_cpu"

    @parameter
    def bench_encrypt_block() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt(block)

    @parameter
    def bench_encrypt_blocks() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(NBLOCKS):
            block = cipher.encrypt(block)

    @parameter
    def bench_decrypt_block() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt(block)

    @parameter
    def bench_decrypt_blocks() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(NBLOCKS):
            block = cipher.decrypt(block)

    print(prefix + "_encrypt_block")
    run[bench_encrypt_block]().print()
    print(prefix + "_encrypt_blocks")
    run[bench_encrypt_blocks]().print()
    print(prefix + "_decrypt_block")
    run[bench_decrypt_block]().print()
    print(prefix + "_decrypt_blocks")
    run[bench_decrypt_blocks]().print()


def bench_gpu_cipher[
    C: BlockCipher & GpuBlockCipher,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) capturing[_] -> C,
    label: StringLiteral,
](ctx: DeviceContext, key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label) + "_gpu"

    # ctx.synchronize() is required for accurate wall-time measurement —
    # enqueue_copy_to is async and returns before the GPU finishes without it.

    @parameter
    def bench_encrypt_1blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[GPU_BLOCKS_1](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_encrypt_256blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[GPU_BLOCKS_256](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_encrypt_1kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[GPU_BLOCKS_1K](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_encrypt_4kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[GPU_BLOCKS_4K](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_1blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[GPU_BLOCKS_1](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_256blk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[GPU_BLOCKS_256](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_1kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[GPU_BLOCKS_1K](ctx, block)
        ctx.synchronize()

    @parameter
    def bench_decrypt_4kblk() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[GPU_BLOCKS_4K](ctx, block)
        ctx.synchronize()

    print(prefix + "_encrypt_1blk")
    run[bench_encrypt_1blk]().print()
    print(prefix + "_encrypt_256blk")
    run[bench_encrypt_256blk]().print()
    print(prefix + "_encrypt_1kblk")
    run[bench_encrypt_1kblk]().print()
    print(prefix + "_encrypt_4kblk")
    run[bench_encrypt_4kblk]().print()
    print(prefix + "_decrypt_1blk")
    run[bench_decrypt_1blk]().print()
    print(prefix + "_decrypt_256blk")
    run[bench_decrypt_256blk]().print()
    print(prefix + "_decrypt_1kblk")
    run[bench_decrypt_1kblk]().print()
    print(prefix + "_decrypt_4kblk")
    run[bench_decrypt_4kblk]().print()


def main() raises:
    bench_cpu_cipher[Aes[16], 16, aes[16], "aes128"](
        InlineArray[UInt8, 16](fill=0)
    )
    # bench_cpu_cipher[Aes[24], 24, aes[24], "aes192"](InlineArray[UInt8, 24](fill=0))
    # bench_cpu_cipher[Aes[32], 32, aes[32], "aes256"](InlineArray[UInt8, 32](fill=0))

    with DeviceContext() as ctx:
        bench_gpu_cipher[Aes[16], 16, aes[16], "aes128"](
            ctx, InlineArray[UInt8, 16](fill=0)
        )
        # bench_gpu_cipher[Aes[24], 24, aes[24], "aes192"](ctx, InlineArray[UInt8, 24](fill=0))
        # bench_gpu_cipher[Aes[32], 32, aes[32], "aes256"](ctx, InlineArray[UInt8, 32](fill=0))
