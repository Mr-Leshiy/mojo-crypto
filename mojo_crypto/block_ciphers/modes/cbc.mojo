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
        var num_blocks = len(data) // BLOCK_SIZE
        var iv = self._iv
        for i in range(num_blocks):
            var offset = i * BLOCK_SIZE
            for j in range(BLOCK_SIZE):
                data[offset + j] ^= iv[j]
            self._cipher.encrypt(data[offset : offset + BLOCK_SIZE])
            for j in range(BLOCK_SIZE):
                iv[j] = data[offset + j]

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        var num_blocks = len(data) // BLOCK_SIZE
        var iv = self._iv
        for i in range(num_blocks):
            var offset = i * BLOCK_SIZE
            var saved = InlineArray[UInt8, 16](fill=0)
            for j in range(BLOCK_SIZE):
                saved[j] = data[offset + j]
            self._cipher.decrypt(data[offset : offset + BLOCK_SIZE])
            for j in range(BLOCK_SIZE):
                data[offset + j] ^= iv[j]
            iv = saved^


# CBC-MAC: IV fixed to zero, returns the final ciphertext block.
# Used as a building block for CCM and SIV.
def cbc_mac[
    C: BlockCipher & Movable & ImplicitlyDestructible, o: MutOrigin
](var cipher: C, data: Span[UInt8, o]) raises -> InlineArray[UInt8, 16]:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    var num_blocks = len(data) // BLOCK_SIZE
    var acc = InlineArray[UInt8, 16](fill=0)
    for i in range(num_blocks):
        var offset = i * BLOCK_SIZE
        for j in range(BLOCK_SIZE):
            acc[j] ^= data[offset + j]
        cipher.encrypt(acc)
    return acc^
