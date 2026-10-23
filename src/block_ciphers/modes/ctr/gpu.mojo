from warp import Context

from ....utils import load_bytes, to_bytes, yield_now
from ...traits import (
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
)
from .common import _check_params, _increment_ctr, _xor_keystream


struct GpuCtrMode[
    C: AsyncBlockCipherEncryptable
    & AsyncBlockCipherDecryptable
    & Movable
    & Deinitable,
    SIZE: Int = C.BLOCK_SIZE,
    BIG_ENDIAN: Bool = True,
](
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
    Deinitable,
    Movable,
):
    """Counter (CTR) block cipher mode over an async (device-backed) cipher.

    NIST SP 800-38A, Section 6.5:
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    Each keystream block is produced by its own awaited cipher call. `SIZE`
    and `BIG_ENDIAN` are as in `CtrMode`.
    """

    comptime BLOCK_SIZE: Int = Self.C.BLOCK_SIZE

    var _cipher: Self.C
    var _ctr: SIMD[DType.uint8, Self.BLOCK_SIZE]

    def __init__(
        out self,
        var cipher: Self.C,
        var ctr: Array[UInt8, Self.BLOCK_SIZE],
    ):
        """Initialize from a fully-assembled initial counter block."""

        _check_params[Self.BLOCK_SIZE, Self.SIZE]()

        self._cipher = cipher^
        self._ctr = load_bytes[dtype=DType.uint8, width=Self.BLOCK_SIZE](ctr)

    __async def encrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        __await self._apply(ctx, data)

    __async def decrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        __await self._apply(ctx, data)

    __async def _apply[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        # `_apply` is awaited by `encrypt`/`decrypt` and would finish without
        # suspending on an empty `data`, so it suspends first (see `yield_now`).
        __await yield_now(ctx)
        var offset = 0
        while offset < len(data):
            # The keystream block is E(counter). The cipher works on bytes, so
            # the counter goes out as an array.
            var keystream = to_bytes[
                input_size=Self.BLOCK_SIZE, output_size=Self.BLOCK_SIZE
            ](self._ctr)
            __await self._cipher.encrypt(ctx, Span(keystream))

            var end = min(offset + Self.BLOCK_SIZE, len(data))
            _xor_keystream[Self.BLOCK_SIZE](data[offset:end], Span(keystream))

            _increment_ctr[Self.SIZE, Self.BIG_ENDIAN](self._ctr)
            offset += Self.BLOCK_SIZE
