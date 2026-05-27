from mojo_crypto.block_ciphers.traits import BlockCipher
from mojo_crypto.block_ciphers.errors import BlockSizeError


comptime BLOCK_SIZE: Int = 16


struct CbcMode[Cipher: BlockCipher & Movable & ImplicitlyDestructible](
    BlockCipher, ImplicitlyDestructible
):
    var _cipher: Self.Cipher
    var _iv: InlineArray[UInt8, 16]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        iv: InlineArray[UInt8, 16],
    ):
        self._cipher = cipher^
        self._iv = iv

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        cbc_encrypt(self._cipher, self._iv, data)
        if len(data) > 0:
            var offset = len(data) - BLOCK_SIZE
            for j in range(BLOCK_SIZE):
                self._iv[j] = data[offset + j]

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        # Save last ciphertext block before it is overwritten by decryption.
        var next_iv = self._iv
        if len(data) > 0:
            var offset = len(data) - BLOCK_SIZE
            for j in range(BLOCK_SIZE):
                next_iv[j] = data[offset + j]
        cbc_decrypt(self._cipher, self._iv, data)
        self._iv = next_iv^


def cbc_encrypt[C: BlockCipher, o: MutOrigin](
    mut cipher: C,
    iv: InlineArray[UInt8, 16],
    data: Span[UInt8, o],
) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    var num_blocks = len(data) // BLOCK_SIZE
    var prev = iv
    for i in range(num_blocks):
        var offset = i * BLOCK_SIZE
        for j in range(BLOCK_SIZE):
            data[offset + j] ^= prev[j]
        cipher.encrypt(data[offset : offset + BLOCK_SIZE])
        for j in range(BLOCK_SIZE):
            prev[j] = data[offset + j]


def cbc_decrypt[C: BlockCipher, o: MutOrigin](
    mut cipher: C,
    iv: InlineArray[UInt8, 16],
    data: Span[UInt8, o],
) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    var num_blocks = len(data) // BLOCK_SIZE
    var prev = iv
    for i in range(num_blocks):
        var offset = i * BLOCK_SIZE
        var saved = InlineArray[UInt8, 16](fill=0)
        for j in range(BLOCK_SIZE):
            saved[j] = data[offset + j]
        cipher.decrypt(data[offset : offset + BLOCK_SIZE])
        for j in range(BLOCK_SIZE):
            data[offset + j] ^= prev[j]
        prev = saved^


# CBC-MAC: IV fixed to zero, returns the final ciphertext block.
# Used as a building block for CCM and SIV.
def cbc_mac[C: BlockCipher, o: MutOrigin](
    mut cipher: C,
    data: Span[UInt8, o],
) raises -> InlineArray[UInt8, 16]:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    var num_blocks = len(data) // BLOCK_SIZE
    var acc = InlineArray[UInt8, 16](fill=0)
    for i in range(num_blocks):
        var offset = i * BLOCK_SIZE
        for j in range(BLOCK_SIZE):
            acc[j] ^= data[offset + j]
        cipher.encrypt(acc)
    return acc^
