from mojo_crypto.utils import load_bytes, store_bytes
from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.errors import BlockSizeError


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
        self._iv = load_bytes[dtype=DType.uint8, width=Self.BLOCK_SIZE](iv)

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        var num_blocks = len(data) // Self.BLOCK_SIZE

        for i in range(num_blocks):
            var offset = i * Self.BLOCK_SIZE

            var data_span = data[offset : offset + Self.BLOCK_SIZE]
            var data_simd = load_bytes[
                dtype=DType.uint8, width=Self.BLOCK_SIZE
            ](data_span)

            data_simd ^= self._iv
            store_bytes(data_span, data_simd)

            self._cipher.encrypt(data_span)

            self._iv = load_bytes[dtype=DType.uint8, width=Self.BLOCK_SIZE](
                data_span
            )

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))
        var num_blocks = len(data) // Self.BLOCK_SIZE
        for i in range(num_blocks):
            var offset = i * Self.BLOCK_SIZE
            var data_span = data[offset : offset + Self.BLOCK_SIZE]
            var saved = load_bytes[dtype=DType.uint8, width=Self.BLOCK_SIZE](
                data_span
            )

            self._cipher.decrypt(data_span)

            var data_simd = load_bytes[
                dtype=DType.uint8, width=Self.BLOCK_SIZE
            ](data_span)
            data_simd ^= self._iv
            store_bytes(data_span, data_simd)

            self._iv = saved
