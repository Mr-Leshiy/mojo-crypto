from ...traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from ...errors import BlockSizeError
from ....utils import load_bytes, store_bytes


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
        """Initialize from an already-keyed cipher and an IV."""
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


@always_inline
def _block[
    o: Origin, //, BLOCK_SIZE: Int
](data: Span[UInt8, o], i: Int) -> Span[UInt8, o]:
    return Span[UInt8, o](
        unsafe_ptr=data.unsafe_ptr().unsafe_offset(i * BLOCK_SIZE),
        length=BLOCK_SIZE,
    )


@always_inline
def _load_block[
    o: Origin, //, BLOCK_SIZE: Int
](block: Span[UInt8, o]) -> SIMD[DType.uint8, BLOCK_SIZE]:
    return load_bytes[dtype=DType.uint8, width=BLOCK_SIZE](block)


@always_inline
def _xor_block[
    o: MutOrigin, BLOCK_SIZE: Int, //
](block: Span[UInt8, o], value: SIMD[DType.uint8, BLOCK_SIZE]):
    store_bytes(block, _load_block[BLOCK_SIZE](block) ^ value)
