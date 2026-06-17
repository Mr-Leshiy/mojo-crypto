from mojo_crypto.universal_hashes.traits import UniversalHashable
from .field_element import FieldElement
from .common import (
    BLOCK_SIZE,
    KEY_SIZE,
    TAG_SIZE,
)


trait Pmull:
    """A 64×64 → 128-bit carry-less multiply backend.

    Provided as a type parameter (rather than a `capturing` function value) so
    that `PolyvalRf`'s methods stay non-capturing and can satisfy the
    `UniversalHashable` trait. Backends (`PolyvalAarch64`, `PolyvalX86`) supply
    the platform PMULL/PCLMULQDQ intrinsic as a static method.
    """

    @staticmethod
    def mul(a: UInt64, b: UInt64) -> SIMD[DType.uint64, 2]:
        """Carry-less product of the low 64 bits of `a` and `b`."""
        ...


struct PolyvalRf[P: Pmull](
    Copyable, ImplicitlyDestructible, Movable, UniversalHashable
):
    """
    optimized POLYVAL implementation using R/F Algorithm

    Adapted from the implementation in the Apache 2.0 + MIT-licensed HPCrypt library
    Copyright (c) 2024 HPCrypt Contributors

    This implementation uses the R/F (Reduction/Field) algorithm:
    - 4 PMULL per block for R and F terms
    - PMULL-based reduction (1 PMULL) instead of scalar shifts
    - 4-block aggregated processing with single reduction

    Key equations:
    - D = swap(H) ⊕ (H0 × P1)
    - R = M0×D1 ⊕ M1×H1
    - F = M0×D0 ⊕ M1×H0
    - Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)

    POLYVAL operates in GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1
    Unlike GHASH, POLYVAL uses little-endian byte ordering (no byte swap needed).

    <https://eprint.iacr.org/2025/2171.pdf>
    """

    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime KEY_SIZE: Int = KEY_SIZE
    comptime TAG_SIZE: Int = TAG_SIZE

    var _h: ExpandedKey[Self.P]
    var _y: FieldElement

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        self._h = ExpandedKey[Self.P](h)
        self._y = FieldElement.zeros()

    def update_block(mut self, block: InlineArray[UInt8, Self.BLOCK_SIZE]):
        """Absorb one block into the accumulator: y = (y ⊕ block) × H."""
        data = load_bytes(block)
        y = load_bytes(self._y._v)
        h1 = load_bytes(self._h.h1._v)
        d1 = load_bytes(self._h.d1._v)

        # XOR with accumulator
        acc = y ^ data

        # Multiply by H using R/F algorithm
        self._y = FieldElement(
            store_bytes(gf128_mul_rf[Self.P](acc, h1, d1))
        )

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return self._y._v


# P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
comptime P1: UInt64 = 0xC200_0000_0000_0000


@fieldwise_init
struct ExpandedKey[P: Pmull](
    Copyable, Equatable, ImplicitlyDestructible, Movable, Writable
):
    """
    Precomputed key material for POLYVAL using R/F algorithm

    Stores H and D values for each power, where D = swap(H) ⊕ (H0 × P1)

    Only h1/d1 are needed for single-block processing (update_block). The
    higher powers h2/d2 .. h4/d4 are precomputed for 4-block aggregated
    processing (update_par_blocks), which multiplies each of the 4 blocks by a
    different power of H and reduces once — added later.
    """

    # H^1 packed as [h1_hi : h1_lo]
    var h1: FieldElement
    # D^1 = computed from H^1
    var d1: FieldElement
    # H^2
    var h2: FieldElement
    # D^2
    var d2: FieldElement
    # H^3
    var h3: FieldElement
    # D^3
    var d3: FieldElement
    # H^4
    var h4: FieldElement
    # D^4
    var d4: FieldElement

    def __init__(out self, h: InlineArray[UInt8, KEY_SIZE]):
        h1 = load_bytes(h)
        d1 = compute_d[Self.P](h1)

        h2 = gf128_mul_rf[Self.P](h1, h1, d1)
        d2 = compute_d[Self.P](h2)

        h3 = gf128_mul_rf[Self.P](h2, h1, d1)
        d3 = compute_d[Self.P](h3)

        h4 = gf128_mul_rf[Self.P](h2, h2, d2)
        d4 = compute_d[Self.P](h4)

        self.h1 = FieldElement(store_bytes(h1))
        self.d1 = FieldElement(store_bytes(d1))
        self.h2 = FieldElement(store_bytes(h2))
        self.d2 = FieldElement(store_bytes(d2))
        self.h3 = FieldElement(store_bytes(h3))
        self.d3 = FieldElement(store_bytes(d3))
        self.h4 = FieldElement(store_bytes(h4))
        self.d4 = FieldElement(store_bytes(d4))

    @staticmethod
    def zeros() -> Self:
        return Self(
            h1=FieldElement.zeros(),
            d1=FieldElement.zeros(),
            h2=FieldElement.zeros(),
            d2=FieldElement.zeros(),
            h3=FieldElement.zeros(),
            d3=FieldElement.zeros(),
            h4=FieldElement.zeros(),
            d4=FieldElement.zeros(),
        )


@always_inline
def load_bytes(bytes: InlineArray[UInt8, 16]) -> SIMD[DType.uint64, 2]:
    """Load 16 bytes as two 64-bit lanes."""
    return bytes.unsafe_ptr().bitcast[UInt64]().load[width=2]()


@always_inline
def store_bytes(reg: SIMD[DType.uint64, 2]) -> InlineArray[UInt8, 16]:
    """Store two 64-bit lanes back into 16 bytes."""
    out = InlineArray[UInt8, 16](uninitialized=True)
    out.unsafe_ptr().bitcast[UInt64]().store(reg)
    return out^


@always_inline
def compute_d[
    P: Pmull
](h: SIMD[DType.uint64, 2]) -> SIMD[DType.uint64, 2]:
    """
    Compute D = swap(H) ⊕ (H0 × P1) for the R/F algorithm.

    The lane swap turns [H0:H1] into [H1:H0]; P.mul(H0, P1) is the
    carry-less product of the low lane against the reduction constant.
    """

    h_swap = SIMD[DType.uint64, 2](h[1], h[0])
    t = P.mul(h[0], P1)
    return h_swap ^ t


@always_inline
def gf128_mul_rf[
    P: Pmull
](
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    """Complete R/F multiplication with reduction (5 PCLMULQDQs total)."""

    rf = rf_mul_unreduced[P](m, h, d)
    return reduce_rf[P](rf[0], rf[1])


@always_inline
def rf_mul_unreduced[
    P: Pmull
](
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> Tuple[SIMD[DType.uint64, 2], SIMD[DType.uint64, 2]]:
    """
    R/F multiplication: compute R and F terms without reduction (4 PCLMULQDQs).

    R = M0×D1 ⊕ M1×H1
    F = M0×D0 ⊕ M1×H0
    """

    r = P.mul(m[0], d[1]) ^ P.mul(m[1], h[1])
    f = P.mul(m[0], d[0]) ^ P.mul(m[1], h[0])
    return (r, f)


@always_inline
def reduce_rf[
    P: Pmull
](r: SIMD[DType.uint64, 2], f: SIMD[DType.uint64, 2]) -> SIMD[DType.uint64, 2]:
    """
    Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)  (1 PCLMULQDQ).

    F1 is the high lane of f; x^64×F0 shifts F0 into the high lane.
    """

    f1_vec = SIMD[DType.uint64, 2](f[1], 0)
    f0_shifted = SIMD[DType.uint64, 2](0, f[0])
    return r ^ f1_vec ^ f0_shifted ^ P.mul(f[0], P1)
