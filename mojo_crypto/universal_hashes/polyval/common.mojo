from mojo_crypto.containers.encoding import HexCpu

comptime BLOCK_SIZE: Int = 16
comptime KEY_SIZE: Int = 16
comptime TAG_SIZE: Int = 16


struct FieldElement(Equatable, Writable):
    var _v: InlineArray[UInt8, BLOCK_SIZE]

    def __init__(out self, v: InlineArray[UInt8, BLOCK_SIZE]):
        self._v = v

    def __add__(self, rhs: Self) -> Self:
        var a: SIMD[DType.uint8, BLOCK_SIZE] = self._v.unsafe_ptr().load[
            width=BLOCK_SIZE
        ]()
        var b: SIMD[DType.uint8, BLOCK_SIZE] = rhs._v.unsafe_ptr().load[
            width=BLOCK_SIZE
        ]()
        var c = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
        c.unsafe_ptr().store(a ^ b)
        return Self(c^)

    def write_to(self, mut writer: Some[Writer]):
        var hex = String()
        try:
            hex = HexCpu().encode(
                Span[UInt8, origin_of(self._v)](
                    ptr=self._v.unsafe_ptr(), length=BLOCK_SIZE
                )
            )
        except:
            pass
        writer.write(hex)
