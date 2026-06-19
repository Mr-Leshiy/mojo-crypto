from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.errors import BlockSizeError


struct CbcMode[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Movable
    & ImplicitlyDestructible
](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Copyable,
    ImplicitlyDestructible,
    Movable,
):
    """
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    Section 6.2
    """

    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _iv: InlineArray[UInt8, Self.Cipher.BLOCK_SIZE]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        iv: InlineArray[UInt8, Self.Cipher.BLOCK_SIZE],
    ):
        self._cipher = cipher^
        self._iv = iv

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))
        var num_blocks = len(data) // Self.BLOCK_SIZE
        for i in range(num_blocks):
            var offset = i * Self.BLOCK_SIZE
            for j in range(Self.BLOCK_SIZE):
                data[offset + j] ^= self._iv[j]
            self._cipher.encrypt(data[offset : offset + Self.BLOCK_SIZE])
            for j in range(Self.BLOCK_SIZE):
                self._iv[j] = data[offset + j]

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))
        var num_blocks = len(data) // Self.BLOCK_SIZE
        for i in range(num_blocks):
            var offset = i * Self.BLOCK_SIZE
            var saved = InlineArray[UInt8, Self.Cipher.BLOCK_SIZE](fill=0)
            for j in range(Self.BLOCK_SIZE):
                saved[j] = data[offset + j]
            self._cipher.decrypt(data[offset : offset + Self.BLOCK_SIZE])
            for j in range(Self.BLOCK_SIZE):
                data[offset + j] ^= self._iv[j]
            self._iv = saved^
