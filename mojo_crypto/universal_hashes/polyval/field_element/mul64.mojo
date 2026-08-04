# Constant-time 64-bit software POLYVAL multiplication.
#
# Adapted from BearSSL's `ghash_ctmul64.c` (Thomas Pornin, 2016) and the
# RustCrypto `polyval/src/field_element/mul64.rs` port.
#
# Reference: <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c;hb=4b6046412>
#
# Uses a Karatsuba 128×128 → 256-bit carryless product (3 × 64-bit bmul calls
# instead of 4) followed by Montgomery-style reduction mod
# `x^128 + x^127 + x^126 + x^121 + 1` (the POLYVAL irreducible polynomial).

from std.sys.intrinsics import llvm_intrinsic
from std.bit import bit_reverse

from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE


@always_inline
def _bmul64(x: UInt64, y: UInt64) -> UInt64:
    """Carryless multiplication in GF(2)[X], result truncated to 64 bits.

    Uses a 4-bit interleaved "holes" decomposition so that carries land in
    zero gaps and are discarded, avoiding the need for a widening multiply.
    Mask pattern: m0 = 0x1111…, m1 = 0x2222…, m2 = 0x4444…, m3 = 0x8888….
    """
    var m0: UInt64 = 0x1111_1111_1111_1111
    var m1 = m0 << 1
    var m2 = m1 << 1
    var m3 = m2 << 1

    var x0 = x & m0
    var x1 = x & m1
    var x2 = x & m2
    var x3 = x & m3

    var y0 = y & m0
    var y1 = y & m1
    var y2 = y & m2
    var y3 = y & m3

    var z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
    var z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
    var z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
    var z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
    return (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3)


@always_inline
def _rev64(x: UInt64) -> UInt64:
    return llvm_intrinsic["llvm.bitreverse.i64", UInt64](x)


struct Product64(Copyable, Movable):
    """Unreduced 256-bit carryless product stored as four 64-bit limbs (lo … hi).
    """

    var _zw: InlineArray[UInt64, 4]

    def __init__(out self, var zw: InlineArray[UInt64, 4]):
        self._zw = zw^

    def mont_reduce(self) -> InlineArray[UInt8, BLOCK_SIZE]:
        """Reduce mod `x^128 + x^127 + x^126 + x^121 + 1` using shift/XOR folding.
        """

        var v0 = self._zw[0]
        var v1 = self._zw[1]
        var v2 = self._zw[2]
        var v3 = self._zw[3]

        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)

        # `as_bytes` is typed `Array[UInt8, size_of[Self]()]`; the size
        # expression is not folded at parse time, so rebind it to BLOCK_SIZE.
        var out = SIMD[DType.uint64, 2](v2, v3).as_bytes()
        return rebind[InlineArray[UInt8, BLOCK_SIZE]](out).copy()


def _karatsuba_mul64(
    a: InlineArray[UInt8, BLOCK_SIZE], b: InlineArray[UInt8, BLOCK_SIZE]
) -> Product64:
    """Compute the unreduced 256-bit carryless product of two 128-bit field elements.

    Uses a Karatsuba decomposition that reduces three 64×64 carryless
    multiplications together with bit-reversal to recover the high half.
    """

    var h = SIMD[DType.uint64, 2].from_bytes(a)
    var hr = bit_reverse(h)
    var h2 = h[0] ^ h[1]
    var hr2 = hr[0] ^ hr[1]

    var y = SIMD[DType.uint64, 2].from_bytes(b)
    var yr = bit_reverse(y)
    var y2 = y[0] ^ y[1]
    var yr2 = yr[0] ^ yr[1]

    var z0 = _bmul64(y[0], h[0])
    var z1 = _bmul64(y[1], h[1])
    var z2 = _bmul64(y2, h2)

    var z0h = _bmul64(yr[0], hr[0])
    var z1h = _bmul64(yr[1], hr[1])
    var z2h = _bmul64(yr2, hr2)

    z2 ^= z0 ^ z1
    z2h ^= z0h ^ z1h
    z0h = _rev64(z0h) >> 1
    z1h = _rev64(z1h) >> 1
    z2h = _rev64(z2h) >> 1

    var zw = InlineArray[UInt64, 4](uninitialized=True)
    zw[0] = z0
    zw[1] = z0h ^ z2
    zw[2] = z1 ^ z2h
    zw[3] = z1h
    return Product64(zw^)
