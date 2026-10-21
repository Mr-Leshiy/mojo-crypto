from ....utils import load_bytes, store_bytes


@always_inline
def _block[
    o: Origin, //, BLOCK_SIZE: Int
](data: Span[UInt8, o], i: Int) -> Span[UInt8, o]:
    return Span[UInt8, o](
        unsafe_ptr=data.unsafe_ptr().unsafe_offset(i * BLOCK_SIZE),
        length=BLOCK_SIZE,
    )


@always_inline
def _load_block[
    o: Origin, //, BLOCK_SIZE: Int
](block: Span[UInt8, o]) -> SIMD[DType.uint8, BLOCK_SIZE]:
    return load_bytes[dtype=DType.uint8, width=BLOCK_SIZE](block)


@always_inline
def _xor_block[
    o: MutOrigin, BLOCK_SIZE: Int, //
](block: Span[UInt8, o], value: SIMD[DType.uint8, BLOCK_SIZE]):
    store_bytes(block, _load_block[BLOCK_SIZE](block) ^ value)
