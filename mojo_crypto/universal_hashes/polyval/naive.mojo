from mojo_crypto.universal_hashes.traits import UniversalHashable
from .field_element import FieldElement
from ._common import BLOCK_SIZE, KEY_SIZE, TAG_SIZE


struct PolyvalNaive(
    Copyable, ImplicitlyDestructible, Movable, UniversalHashable
):
    """Portable software POLYVAL implementation.

    Reference: <https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/soft.rs>
    """

    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime KEY_SIZE: Int = KEY_SIZE
    comptime TAG_SIZE: Int = TAG_SIZE

    var _h: FieldElement
    var _y: FieldElement

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        self._h = FieldElement(h)
        self._y = FieldElement.zeros()

    def update_block(mut self, block: InlineArray[UInt8, Self.BLOCK_SIZE]):
        self._y = (self._y + FieldElement(block)) * self._h

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return self._y._v

    def reset(mut self):
        self._y = FieldElement.zeros()
