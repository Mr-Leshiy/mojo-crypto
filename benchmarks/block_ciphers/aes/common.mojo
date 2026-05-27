from std.benchmark import run

from mojo_crypto.block_ciphers.traits import BlockCipher

comptime BLOCKS_4K: Int = 4_096
comptime BLOCKS_8K: Int = 8_192
comptime BLOCKS_16K: Int = 16_384


def bench_cipher[
    C: BlockCipher & ImplicitlyDestructible,
    KeySize: Int,
    cipher_init: def(InlineArray[UInt8, KeySize]) raises capturing[_] -> C,
    prefix: StringLiteral,
]() raises:
    var key = InlineArray[UInt8, KeySize](fill=0)
    var cipher = cipher_init(key)

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
