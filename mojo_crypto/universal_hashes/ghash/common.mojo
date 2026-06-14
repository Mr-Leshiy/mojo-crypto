from sys import abort

comptime BLOCK_SIZE: Int = 16
comptime KEY_SIZE: Int = 16
comptime TAG_SIZE: Int = 16

# GCM operates in the reflected bit domain: bit 0 of byte 0 is the most
# significant coefficient. The reduction polynomial x^128+x^7+x^2+x+1
# appears as R below in that reflected representation. All backends operate
# in this domain so no per-block reflection is needed at call sites.
comptime R_HI: UInt64 = 0xE100000000000000
comptime R_LO: UInt64 = 0x0000000000000000


# Pack a 16-byte block (GCM big-endian byte order) into SIMD[DType.uint64, 2].
# hi = bytes 0..7, lo = bytes 8..15.
def block_to_u64x2(block: InlineArray[UInt8, 16]) -> SIMD[DType.uint64, 2]:
    return abort[SIMD[DType.uint64, 2]]("not yet implemented")


# Unpack SIMD[DType.uint64, 2] back to a 16-byte block in GCM byte order.
def u64x2_to_block(v: SIMD[DType.uint64, 2]) -> InlineArray[UInt8, 16]:
    return abort[InlineArray[UInt8, 16]]("not yet implemented")
