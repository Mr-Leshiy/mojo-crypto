from ...traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from ...errors import BlockSizeError
from .common import _block, _load_block, _xor_block


struct CbcMode[
    Cipher: BlockCipherEncryptable
    & BlockCipherDecryptable
    & Copyable
    & Deinitable
](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Copyable,
    Deinitable,
    Movable,
):
    """CBC block cipher mode of operation.

    See [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf),
    Section 6.2.
    """

    comptime BLOCK_SIZE: Int = Self.Cipher.BLOCK_SIZE

    var _cipher: Self.Cipher
    var _iv: SIMD[DType.uint8, Self.BLOCK_SIZE]

    def __init__(
        out self,
        var cipher: Self.Cipher,
        var iv: Array[UInt8, Self.BLOCK_SIZE],
    ):
        self._cipher = cipher^
        self._iv = _load_block[Self.BLOCK_SIZE](Span(iv))

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        for i in range(len(data) // Self.BLOCK_SIZE):
            var block = _block[Self.BLOCK_SIZE](data, i)
            _xor_block(block, self._iv)
            self._cipher.encrypt(block)
            self._iv = _load_block[Self.BLOCK_SIZE](block)

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        for i in range(len(data) // Self.BLOCK_SIZE):
            var block = _block[Self.BLOCK_SIZE](data, i)
            var saved = _load_block[Self.BLOCK_SIZE](block)
            self._cipher.decrypt(block)
            _xor_block(block, self._iv)
            self._iv = saved
