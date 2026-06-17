from .field_element import FieldElement


@fieldwise_init
struct ExpandedKey(
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
