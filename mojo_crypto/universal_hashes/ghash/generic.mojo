from mojo_crypto.universal_hashes.traits import UniversalHashable


struct GHashGeneric[
    P: Copyable & ImplicitlyDestructible & Movable & UniversalHashable
](Copyable, ImplicitlyDestructible, Movable, UniversalHashable):
    """
    **GHASH**: universal hash over GF(2^128) used by AES-GCM.

    GHASH is a universal hash function used for message authentication in the
    AES-GCM authenticated encryption cipher.

    GHASH is the big-endian counterpart of POLYVAL: every input/output block is
    byte-reversed and the key is run through `mulx` (RFC 8452 Appendix A). This
    struct is parameterized by the underlying POLYVAL backend `P` (e.g.
    `PolyvalCpu`, `PolyvalAarch64`), so the field arithmetic is shared.
    """

    # GHASH's block/key/tag sizes are exactly the underlying POLYVAL's, so
    # arrays threaded through `_poly` unify without a size mismatch.
    comptime BLOCK_SIZE: Int = Self.P.BLOCK_SIZE
    comptime KEY_SIZE: Int = Self.P.KEY_SIZE
    comptime TAG_SIZE: Int = Self.P.TAG_SIZE

    var _poly: Self.P

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        self._poly = Self.P(mulx(reverse(h)))

    def update_block(mut self, block: InlineArray[UInt8, Self.BLOCK_SIZE]):
        self._poly.update_block(reverse(block))

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return reverse(self._poly.copy().finalize())


def reverse[
    SIZE: Int
](var v: InlineArray[UInt8, SIZE]) -> InlineArray[UInt8, SIZE]:
    """
    Reverse this field element at a byte-level of granularity.
    """
    var out = InlineArray[UInt8, SIZE](uninitialized=True)
    out.unsafe_ptr().store(v.unsafe_ptr().load[width=SIZE]().reversed())
    return out^


def mulx[
    SIZE: Int
](var v: InlineArray[UInt8, SIZE]) -> InlineArray[UInt8, SIZE]:
    """
    The `mulX_POLYVAL()` function as defined in [RFC 8452 Appendix A].

    Performs a doubling (multiply by x) over GF(2^128).
    Useful for implementing GHASH in terms of POLYVAL.

    [RFC 8452 Appendix A]: https://tools.ietf.org/html/rfc8452#appendix-A
    """
    # Interpret the 16-byte element as a 128-bit little-endian integer
    # split across two 64-bit halves: lo = bytes[0..8], hi = bytes[8..16].
    var ptr = v.unsafe_ptr().bitcast[UInt64]()
    var lo = ptr.load(0)
    var hi = ptr.load(1)

    var v_hi = hi >> 63  # save the high bit (0 or 1) before shifting

    # Shift the 128-bit value left by 1 (multiply by x)
    hi = (hi << 1) | (lo >> 63)
    lo = lo << 1

    # Reduce mod x^128 + x^127 + x^126 + x^121 + 1:
    # if the high bit was set, XOR with 1 (bit 0) and bits 121, 126, 127.
    # Bits 121/126/127 all live in `hi` at positions 57/62/63 (offset by 64).
    lo ^= v_hi
    hi ^= (v_hi << 57) | (v_hi << 62) | (v_hi << 63)

    var result = InlineArray[UInt8, SIZE](uninitialized=True)
    var out = result.unsafe_ptr().bitcast[UInt64]()
    out.store(0, lo)
    out.store(1, hi)
    return result^
