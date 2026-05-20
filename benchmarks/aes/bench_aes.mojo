from std.benchmark import run

from mojo_crypto.aes import Aes128, Aes192, Aes256
from mojo_crypto.aes.testing_utils import (
    AesKey,
    AesTestVector,
    load_aes_vectors,
)


def main() raises:
    # --- setup: load all vectors before any measurement ---
    var kat_vectors = load_aes_vectors("mojo_crypto/aes/KAT_AES", "ECB")
    var mct_vectors = load_aes_vectors("mojo_crypto/aes/aesmct", "ECB")

    # KAT: one encrypt + decrypt per vector
    @parameter
    def bench_kat():
        for ref v in kat_vectors:
            if v.key.isa[InlineArray[UInt8, 16]]():
                var aes = Aes128(v.key[InlineArray[UInt8, 16]])
                _ = aes.encrypt(v.pt)
                _ = aes.decrypt(v.ct)
            elif v.key.isa[InlineArray[UInt8, 24]]():
                var aes = Aes192(v.key[InlineArray[UInt8, 24]])
                _ = aes.encrypt(v.pt)
                _ = aes.decrypt(v.ct)
            else:
                var aes = Aes256(v.key[InlineArray[UInt8, 32]])
                _ = aes.encrypt(v.pt)
                _ = aes.decrypt(v.ct)

    # MCT: 1000 chained encrypt or decrypt per vector
    comptime MCT_INNER_ITERATIONS = 1000

    @parameter
    def bench_mct():
        for ref v in mct_vectors:
            if v.key.isa[InlineArray[UInt8, 16]]():
                var aes = Aes128(v.key[InlineArray[UInt8, 16]])
                var block = v.pt if v.is_encrypt else v.ct
                for _ in range(MCT_INNER_ITERATIONS):
                    block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                        block
                    )
            elif v.key.isa[InlineArray[UInt8, 24]]():
                var aes = Aes192(v.key[InlineArray[UInt8, 24]])
                var block = v.pt if v.is_encrypt else v.ct
                for _ in range(MCT_INNER_ITERATIONS):
                    block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                        block
                    )
            else:
                var aes = Aes256(v.key[InlineArray[UInt8, 32]])
                var block = v.pt if v.is_encrypt else v.ct
                for _ in range(MCT_INNER_ITERATIONS):
                    block = aes.encrypt(block) if v.is_encrypt else aes.decrypt(
                        block
                    )

    print("aes_kat_ecb")
    run[bench_kat]().print()

    print("aes_mct_ecb")
    run[bench_mct]().print()
