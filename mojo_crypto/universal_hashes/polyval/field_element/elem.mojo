# POLYVAL field element implementation.
#
# Reference implementation: <https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/field_element.rs>
#
# Computes carryless POLYVAL multiplication over GF(2^128) in constant time.
#
# Method described at: <https://www.bearssl.org/constanttime.html#ghash-for-gcm>
#
# POLYVAL multiplication is effectively the little endian equivalent of GHASH multiplication,
# aside from one small detail described here:
#
# <https://crypto.stackexchange.com/questions/66448/how-does-bearssls-gcm-modular-reduction-work/66462#66462>
#
# > The product of two bit-reversed 128-bit polynomials yields the
# > bit-reversed result over 255 bits, not 256. The BearSSL code ends up
# > with a 256-bit result in zw[], and that value is shifted by one bit,
# > because of that reversed convention issue. Thus, the code must
# > include a shifting step to put it back where it should
#
# This shift is unnecessary for POLYVAL (it is in fact what distinguishes POLYVAL from GHASH) and
# has been removed.

from std.sys.info import is_64bit

from mojo_crypto.utils import hex_encode, to_bytes
from mojo_crypto.universal_hashes.polyval.common import BLOCK_SIZE
from mojo_crypto.universal_hashes.polyval.field_element.mul64 import (
    _karatsuba_mul64,
)
from mojo_crypto.universal_hashes.polyval.field_element.mul32 import (
    _karatsuba_mul32,
)


struct FieldElement(Copyable, Deinitable, Equatable, Movable, Writable):
    """An element in POLYVAL's field.

    This type represents an element of the binary field GF(2^128) modulo the irreducible polynomial
    `x^128 + x^127 + x^126 + x^121 + 1` as described in [RFC8452 §3].

    Arithmetic in POLYVAL's field has the following properties:
    - All arithmetic operations are performed modulo the polynomial above.
    - Addition is equivalent to the XOR operation applied to the two field elements
    - Multiplication is carryless

    [RFC8452 §3]: https://tools.ietf.org/html/rfc8452#section-3
    """

    var _v: InlineArray[UInt8, BLOCK_SIZE]

    def __init__(out self, var v: InlineArray[UInt8, BLOCK_SIZE]):
        self._v = v^

    def __init__(out self, v: SIMD[DType.uint64, 2]):
        """Build an element from two 64-bit limbs (low limb first)."""
        self._v = to_bytes[input_size=2, output_size=BLOCK_SIZE](v)

    @staticmethod
    def zeros() -> Self:
        return Self(InlineArray[UInt8, BLOCK_SIZE](fill=0))

    def __add__(self, rhs: Self) -> Self:
        """
        Adds two POLYVAL field elements.

        In POLYVAL's field, addition is the equivalent operation to XOR.
        """

        var a = SIMD[DType.uint8, BLOCK_SIZE].from_bytes(self._v)
        var b = SIMD[DType.uint8, BLOCK_SIZE].from_bytes(rhs._v)

        return Self(
            to_bytes[input_size=BLOCK_SIZE, output_size=BLOCK_SIZE](a ^ b)
        )

    def __mul__(self, rhs: Self) -> Self:
        """Multiply two POLYVAL field elements mod `x^128 + x^127 + x^126 + x^121 + 1`.

        Dispatches to the 64-bit Karatsuba path on 64-bit platforms and the
        32-bit path on 32-bit platforms.
        """
        comptime if is_64bit():
            return Self(_karatsuba_mul64(self._v, rhs._v).mont_reduce())
        else:
            return Self(_karatsuba_mul32(self._v, rhs._v).mont_reduce())

    def __imul__(mut self, rhs: Self):
        self = self * rhs

    def into_bytes(deinit self) -> InlineArray[UInt8, BLOCK_SIZE]:
        """Consume the element and return its BLOCK_SIZE-byte representation.

        Takes `deinit self`, not `var self`: transferring `_v` out dismantles
        the element, which is only permitted when the callee also takes over
        responsibility for destroying it.
        """
        return self._v^

    def write_to(self, mut writer: Some[Writer]):
        var hex = hex_encode(Span(self._v))
        writer.write(hex)
