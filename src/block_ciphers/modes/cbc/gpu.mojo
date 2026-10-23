from warp import Context

from ...traits import (
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
)
from ...errors import BlockSizeError
from ....utils import yield_now
from .common import _block, _load_block, _xor_block


struct GpuCbcMode[
    Cipher: AsyncBlockCipherEncryptable
    & AsyncBlockCipherDecryptable
    & Copyable
    & Deinitable
](
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
    Copyable,
    Deinitable,
    Movable,
):
    """CBC block cipher mode of operation over an async (device-backed) cipher.

    See [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf),
    Section 6.2.

    Both directions await one cipher call per block.
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

    __async def encrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        __await yield_now(ctx)
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        for i in range(len(data) // Self.BLOCK_SIZE):
            var block = _block[Self.BLOCK_SIZE](data, i)
            _xor_block(block, self._iv)
            __await self._cipher.encrypt(ctx, block)
            self._iv = _load_block[Self.BLOCK_SIZE](block)

    __async def decrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        __await yield_now(ctx)
        BlockSizeError[Self.BLOCK_SIZE].check(len(data))

        for i in range(len(data) // Self.BLOCK_SIZE):
            var block = _block[Self.BLOCK_SIZE](data, i)
            var saved = _load_block[Self.BLOCK_SIZE](block)
            __await self._cipher.decrypt(ctx, block)
            _xor_block(block, self._iv)
            self._iv = saved
