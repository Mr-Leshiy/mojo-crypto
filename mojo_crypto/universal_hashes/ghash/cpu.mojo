from mojo_crypto.universal_hashes.traits import UniversalHashable
from mojo_crypto.universal_hashes.errors import UhashSizeError
from mojo_crypto.universal_hashes.polyval import PolyvalCpu
from mojo_crypto.universal_hashes.polyval.field_element import FieldElement
from .common import BLOCK_SIZE, KEY_SIZE, TAG_SIZE


struct GHashCpu(Copyable, ImplicitlyDestructible, Movable, UniversalHashable):
    """**GHASH**: universal hash over GF(2^128) used by AES-GCM.

    GHASH is a universal hash function used for message authentication in the AES-GCM authenticated encryption cipher.
    """

    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime KEY_SIZE: Int = KEY_SIZE
    comptime TAG_SIZE: Int = TAG_SIZE

    var _h: FieldElement
    var _y: FieldElement

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        self._h = FieldElement(h).reverse().mulx()
        self._y = FieldElement.zeros()

    def update[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        UhashSizeError[BLOCK_SIZE].check(len(data))
        for i in range(len(data) // BLOCK_SIZE):
            block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
            block.unsafe_ptr().store(
                (data.unsafe_ptr() + i * BLOCK_SIZE).load[width=BLOCK_SIZE]()
            )
            block_fe = FieldElement(block).reverse()
            self._y = (self._y + block_fe) * self._h

    def finalize(self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return self._y.copy().reverse()._v
