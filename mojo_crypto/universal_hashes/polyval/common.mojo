from .field_element import FieldElement

comptime BLOCK_SIZE: Int = 16
comptime KEY_SIZE: Int = 16
comptime TAG_SIZE: Int = 16

# P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
comptime P1: UInt64 = 0xC200_0000_0000_0000


@fieldwise_init
struct ExpandedKey[
    pmull64: def(a: UInt64, b: UInt64) capturing[_] -> SIMD[DType.uint64, 2]
](Copyable, Equatable, ImplicitlyDestructible, Movable, Writable):
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
        d1 = compute_d[Self.pmull64](h1)

        h2 = gf128_mul_rf[Self.pmull64](h1, h1, d1)
        d2 = compute_d[Self.pmull64](h2)

        h3 = gf128_mul_rf[Self.pmull64](h2, h1, d1)
        d3 = compute_d[Self.pmull64](h3)

        h4 = gf128_mul_rf[Self.pmull64](h2, h2, d2)
        d4 = compute_d[Self.pmull64](h4)

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
    pmull64: def(a: UInt64, b: UInt64) capturing[_] -> SIMD[DType.uint64, 2]
](h: SIMD[DType.uint64, 2]) -> SIMD[DType.uint64, 2]:
    """
    Compute D = swap(H) ⊕ (H0 × P1) for the R/F algorithm.

    The lane swap turns [H0:H1] into [H1:H0]; pmull64(H0, P1) is the
    carry-less product of the low lane against the reduction constant.
    """

    h_swap = SIMD[DType.uint64, 2](h[1], h[0])
    t = pmull64(h[0], P1)
    return h_swap ^ t


@always_inline
def gf128_mul_rf[
    pmull64: def(a: UInt64, b: UInt64) capturing[_] -> SIMD[DType.uint64, 2]
](
    m: SIMD[DType.uint64, 2],
    h: SIMD[DType.uint64, 2],
    d: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    """Complete R/F multiplication with reduction (5 PCLMULQDQs total)."""

    rf = rf_mul_unreduced[pmull64](m, h, d)
    return reduce_rf[pmull64](rf[0], rf[1])


@always_inline
def rf_mul_unreduced[
    pmull64: def(a: UInt64, b: UInt64) capturing[_] -> SIMD[DType.uint64, 2]
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

    r = pmull64(m[0], d[1]) ^ pmull64(m[1], h[1])
    f = pmull64(m[0], d[0]) ^ pmull64(m[1], h[0])
    return (r, f)


@always_inline
def reduce_rf[
    pmull64: def(a: UInt64, b: UInt64) capturing[_] -> SIMD[DType.uint64, 2]
](r: SIMD[DType.uint64, 2], f: SIMD[DType.uint64, 2]) -> SIMD[DType.uint64, 2]:
    """
    Reduction using Lemma 3: Result = R ⊕ F1 ⊕ (x^64×F0) ⊕ (P1×F0)  (1 PCLMULQDQ).

    F1 is the high lane of f; x^64×F0 shifts F0 into the high lane.
    """

    f1_vec = SIMD[DType.uint64, 2](f[1], 0)
    f0_shifted = SIMD[DType.uint64, 2](0, f[0])
    return r ^ f1_vec ^ f0_shifted ^ pmull64(f[0], P1)
