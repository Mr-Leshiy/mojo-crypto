from std.benchmark import run

from mojo_crypto.aes import Aes, AesGpu, BLOCK_SIZE
from mojo_crypto.block_cipher import BlockCipher

comptime NBLOCKS: Int = 1024


@parameter
def aes[KeySize: Int](key: InlineArray[UInt8, KeySize]) -> Aes[KeySize]:
    return Aes[KeySize](key)


def bench_cipher[
    C: BlockCipher,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) capturing[_] -> C,
    label: StringLiteral,
](key: InlineArray[UInt8, KeySize]) raises:
    var cipher = cipher_init(key)
    var prefix = String(label)

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


def main() raises:
    bench_cipher[Aes[16], 16, aes[16], "aes128"](InlineArray[UInt8, 16](fill=0))
    bench_cipher[Aes[24], 24, aes[24], "aes192"](InlineArray[UInt8, 24](fill=0))
    bench_cipher[Aes[32], 32, aes[32], "aes256"](InlineArray[UInt8, 32](fill=0))
