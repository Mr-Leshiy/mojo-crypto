from std.benchmark import run
from std.gpu.host import DeviceContext

from mojo_crypto.aes import Aes, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher, GpuBlockCipher

comptime NBLOCKS: Int = 1024
comptime BLOCKS_PER_GRID: Int = 1


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

    @parameter
    def bench_gpu_encrypt_block() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.encrypt[BLOCKS_PER_GRID](ctx, block)

    @parameter
    def bench_gpu_encrypt_blocks() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(NBLOCKS):
            block = cipher.encrypt[BLOCKS_PER_GRID](ctx, block)

    @parameter
    def bench_gpu_decrypt_block() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        _ = cipher.decrypt[BLOCKS_PER_GRID](ctx, block)

    @parameter
    def bench_gpu_decrypt_blocks() raises:
        var block = InlineArray[UInt8, BLOCK_SIZE](fill=0)
        for _ in range(NBLOCKS):
            block = cipher.decrypt[BLOCKS_PER_GRID](ctx, block)

    print(prefix + "_encrypt_block")
    run[bench_gpu_encrypt_block]().print()
    print(prefix + "_encrypt_blocks")
    run[bench_gpu_encrypt_blocks]().print()
    print(prefix + "_decrypt_block")
    run[bench_gpu_decrypt_block]().print()
    print(prefix + "_decrypt_blocks")
    run[bench_gpu_decrypt_blocks]().print()


def main() raises:
    bench_cpu_cipher[Aes[16], 16, aes[16], "aes128"](InlineArray[UInt8, 16](fill=0))
    # bench_cpu_cipher[Aes[24], 24, aes[24], "aes192"](InlineArray[UInt8, 24](fill=0))
    # bench_cpu_cipher[Aes[32], 32, aes[32], "aes256"](InlineArray[UInt8, 32](fill=0))

    with DeviceContext() as ctx:
        bench_gpu_cipher[Aes[16], 16, aes[16], "aes128"](ctx, InlineArray[UInt8, 16](fill=0))
        # bench_gpu_cipher[Aes[24], 24, aes[24], "aes192"](ctx, InlineArray[UInt8, 24](fill=0))
        # bench_gpu_cipher[Aes[32], 32, aes[32], "aes256"](ctx, InlineArray[UInt8, 32](fill=0))
