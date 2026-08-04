# Constant-time 32-bit software POLYVAL multiplication.
#
# Adapted from BearSSL's `ghash_ctmul32.c` (Thomas Pornin, 2016) and the
# RustCrypto `polyval/src/field_element/mul32.rs` port.
#
# Reference: <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul32.c;hb=4b6046412>
#
# Designed for 32-bit CPUs without a widening multiply (e.g. ARM Cortex-M0/M0+).
# Uses the bit-reversal trick: for GF(2)[X], x.reverse_bits() * y.reverse_bits()
# == (x * y).reverse_bits(), allowing the 64-bit high half of each 32×32
# product to be recovered by bit-reversing the low half of the reversed inputs.
#
# The 128×128 multiplication is decomposed into 9 × 32×32 sub-products via
# Karatsuba; with the bit-reversal twin we perform 18 × 32-bit bmul calls.

from std.bit import bit_reverse

from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE


@always_inline
def _bmul32(x: UInt32, y: UInt32) -> UInt32:
    """Carryless multiplication in GF(2)[X], result truncated to 32 bits.

    Same "holes" decomposition as the 64-bit variant with m0 = 0x11111111.
    """
    var m0: UInt32 = 0x1111_1111
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
def _rev32[
    width: Int, //
](x: SIMD[DType.uint32, width]) -> SIMD[DType.uint32, width]:
    """Bit-reverse each 32-bit lane; `width=1` covers the scalar call sites."""
    return bit_reverse(x)


struct Product32(Copyable, Movable):
    """Unreduced 256-bit carryless product stored as eight 32-bit limbs (lo … hi).
    """

    var _zw: InlineArray[UInt32, 8]

    def __init__(out self, var zw: InlineArray[UInt32, 8]):
        self._zw = zw^

    def mont_reduce(self) -> InlineArray[UInt8, BLOCK_SIZE]:
        """Reduce mod `x^128 + x^127 + x^126 + x^121 + 1` using shift/XOR folding.

        Equivalent to the 64-bit reduction but split across 32-bit limbs.
        zw[3] is updated in i=0 and read back as `lw` in i=3 — the sequential
        dependency is load-bearing, so the loop is unrolled.
        """
        var zw = self._zw.copy()
        # i=0
        var lw = zw[0]
        zw[4] = zw[4] ^ lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7)
        zw[3] = zw[3] ^ ((lw << 31) ^ (lw << 30) ^ (lw << 25))
        # i=1
        lw = zw[1]
        zw[5] = zw[5] ^ lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7)
        zw[4] = zw[4] ^ ((lw << 31) ^ (lw << 30) ^ (lw << 25))
        # i=2
        lw = zw[2]
        zw[6] = zw[6] ^ lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7)
        zw[5] = zw[5] ^ ((lw << 31) ^ (lw << 30) ^ (lw << 25))
        # i=3: reads the zw[3] updated in i=0
        lw = zw[3]
        zw[7] = zw[7] ^ lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7)
        zw[6] = zw[6] ^ ((lw << 31) ^ (lw << 30) ^ (lw << 25))
        # `as_bytes` is typed `Array[UInt8, size_of[Self]()]`; the size expression
        # is not folded at parse time, so rebind it to the declared BLOCK_SIZE.
        var out = SIMD[DType.uint32, 4](zw[4], zw[5], zw[6], zw[7]).as_bytes()
        return rebind[InlineArray[UInt8, BLOCK_SIZE]](out).copy()


def _karatsuba_mul32(
    a: InlineArray[UInt8, BLOCK_SIZE], b: InlineArray[UInt8, BLOCK_SIZE]
) -> Product32:
    """Compute the unreduced 256-bit carryless product of two 128-bit field elements.

    Decomposes the 128×128 multiply into 9 × 32×32 Karatsuba sub-products;
    with the bit-reversal trick for the high half, 18 × _bmul32 calls total.
    """
    var yw = SIMD[DType.uint32, 4].from_bytes(a)
    var hw = SIMD[DType.uint32, 4].from_bytes(b)

    var hwr = bit_reverse(hw)

    # Karatsuba decomposition for a (yw limbs)
    var a0 = yw[0]
    var a1 = yw[1]
    var a2 = yw[2]
    var a3 = yw[3]
    var a4 = a0 ^ a1
    var a5 = a2 ^ a3
    var a6 = a0 ^ a2
    var a7 = a1 ^ a3
    var a8 = a6 ^ a7
    var a9 = bit_reverse(yw[0])
    var a10 = bit_reverse(yw[1])
    var a11 = bit_reverse(yw[2])
    var a12 = bit_reverse(yw[3])
    var a13 = a9 ^ a10
    var a14 = a11 ^ a12
    var a15 = a9 ^ a11
    var a16 = a10 ^ a12
    var a17 = a15 ^ a16

    # Karatsuba decomposition for b (hw limbs)
    var b0 = hw[0]
    var b1 = hw[1]
    var b2 = hw[2]
    var b3 = hw[3]
    var b4 = b0 ^ b1
    var b5 = b2 ^ b3
    var b6 = b0 ^ b2
    var b7 = b1 ^ b3
    var b8 = b6 ^ b7
    var b9 = hwr[0]
    var b10 = hwr[1]
    var b11 = hwr[2]
    var b12 = hwr[3]
    var b13 = b9 ^ b10
    var b14 = b11 ^ b12
    var b15 = b9 ^ b11
    var b16 = b10 ^ b12
    var b17 = b15 ^ b16

    # 18 carryless 32×32 multiplications
    var c0 = _bmul32(a0, b0)
    var c1 = _bmul32(a1, b1)
    var c2 = _bmul32(a2, b2)
    var c3 = _bmul32(a3, b3)
    var c4 = _bmul32(a4, b4)
    var c5 = _bmul32(a5, b5)
    var c6 = _bmul32(a6, b6)
    var c7 = _bmul32(a7, b7)
    var c8 = _bmul32(a8, b8)
    var c9 = _bmul32(a9, b9)
    var c10 = _bmul32(a10, b10)
    var c11 = _bmul32(a11, b11)
    var c12 = _bmul32(a12, b12)
    var c13 = _bmul32(a13, b13)
    var c14 = _bmul32(a14, b14)
    var c15 = _bmul32(a15, b15)
    var c16 = _bmul32(a16, b16)
    var c17 = _bmul32(a17, b17)

    # Karatsuba recombination (normal halves)
    c4 ^= c0 ^ c1
    c5 ^= c2 ^ c3
    c8 ^= c6 ^ c7

    # Karatsuba recombination (bit-reversed halves)
    c13 ^= c9 ^ c10
    c14 ^= c11 ^ c12
    c17 ^= c15 ^ c16

    var zw = InlineArray[UInt32, 8](uninitialized=True)
    zw[0] = c0
    zw[1] = c4 ^ (bit_reverse(c9) >> 1)
    zw[2] = c1 ^ c0 ^ c2 ^ c6 ^ (bit_reverse(c13) >> 1)
    zw[3] = c4 ^ c5 ^ c8 ^ (bit_reverse(c10 ^ c9 ^ c11 ^ c15) >> 1)
    zw[4] = c2 ^ c1 ^ c3 ^ c7 ^ (bit_reverse(c13 ^ c14 ^ c17) >> 1)
    zw[5] = c5 ^ (bit_reverse(c11 ^ c10 ^ c12 ^ c16) >> 1)
    zw[6] = c3 ^ (bit_reverse(c14) >> 1)
    zw[7] = bit_reverse(c12) >> 1
    return Product32(zw^)
