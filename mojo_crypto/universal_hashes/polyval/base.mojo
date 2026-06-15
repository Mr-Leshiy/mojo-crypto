from sys import abort

from mojo_crypto.universal_hashes.traits import UniversalHash
from mojo_crypto.universal_hashes.errors import UhashSizeError
from .common import (
    BLOCK_SIZE,
    KEY_SIZE,
    TAG_SIZE,
)


struct PolyvalBase(ImplicitlyDestructible, Movable, UniversalHash):
    comptime BLOCK_SIZE: Int = BLOCK_SIZE
    comptime KEY_SIZE: Int = KEY_SIZE
    comptime TAG_SIZE: Int = TAG_SIZE

    def __init__(out self, h: InlineArray[UInt8, Self.KEY_SIZE]):
        abort("not yet implemented")

    def update[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        abort("not yet implemented")

    def finalize(var self) -> InlineArray[UInt8, Self.TAG_SIZE]:
        return abort[InlineArray[UInt8, Self.TAG_SIZE]]("not yet implemented")
