from std.benchmark import run
from std.sys import get_defined_string

from mojo_crypto.block_ciphers.modes import CbcMode, CtrMode
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)

comptime BLOCKS_4K: Int = 4_096
comptime BLOCKS_8K: Int = 8_192
comptime BLOCKS_16K: Int = 16_384

# Mode of operation to benchmark, picked at build time with `-D MODE=<mode>`
# (the `--mode` option of the bench CLI). `ecb` runs the bare cipher over the
# whole buffer.
comptime MODE = get_defined_string["MODE", "ecb"]()


def bench_engine[
    E: BlockCipherEncryptable & BlockCipherDecryptable & Deinitable
](var engine: E, name: String) raises:
    @__parameter
    def bench[N: Int, suffix: StringLiteral]() raises:
        var data = Array[UInt8, N](fill=0)

        def do_encrypt() raises {mut data, mut engine}:
            engine.encrypt(data)

        def do_decrypt() raises {mut data, mut engine}:
            engine.decrypt(data)

        run(do_encrypt).print(name + "_encrypt_" + suffix)
        run(do_decrypt).print(name + "_decrypt_" + suffix)

    bench[BLOCKS_4K, "4kb"]()
    bench[BLOCKS_8K, "8kb"]()
    bench[BLOCKS_16K, "16kb"]()


def bench_cipher[
    C: BlockCipherEncryptable & BlockCipherDecryptable & Copyable & Deinitable,
    KeySize: Int,
    cipher_init: def(Array[UInt8, KeySize]) raises capturing[_] -> C,
    prefix: StringLiteral,
]() raises:
    var key = Array[UInt8, KeySize](fill=0)
    var iv = Array[UInt8, C.BLOCK_SIZE](fill=0)
    var name = String(prefix, "_", MODE)

    comptime if MODE == "ecb":
        bench_engine(cipher_init(key), name)
    elif MODE == "cbc":
        bench_engine(CbcMode[C](cipher_init(key), iv^), name)
    elif MODE == "ctr":
        bench_engine(CtrMode[C](cipher_init(key), iv^), name)
    else:
        comptime assert False, "MODE must be one of: ecb, cbc, ctr"
