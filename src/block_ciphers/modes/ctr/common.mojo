from ....utils import load_bytes, store_bytes


@always_inline
def _check_params[BLOCK_SIZE: Int, SIZE: Int]():
    comptime assert SIZE > 0, "counter SIZE must be positive"
    comptime assert SIZE <= BLOCK_SIZE, "counter SIZE cannot exceed BLOCK_SIZE"


@always_inline
def _increment_ctr[
    BLOCK_SIZE: Int, //, SIZE: Int, BIG_ENDIAN: Bool
](mut ctr: SIMD[DType.uint8, BLOCK_SIZE]):
    """Increment the `SIZE`-byte counter field of `ctr`.

    The nonce bytes are never carried into (NIST SP 800-38A).
    """
    comptime if BIG_ENDIAN:
        # counter = last SIZE bytes, big-endian
        for i in range(BLOCK_SIZE - 1, BLOCK_SIZE - SIZE - 1, -1):
            ctr[i] += 1
            if ctr[i] != 0:
                break
    else:
        # counter = first SIZE bytes, little-endian
        for i in range(SIZE):
            ctr[i] += 1
            if ctr[i] != 0:
                break


@always_inline
def _xor_keystream[
    o: MutOrigin, ko: Origin, //, BLOCK_SIZE: Int
](data: Span[UInt8, o], keystream: Span[UInt8, ko]):
    """XOR `keystream` over `data`, which must be no longer than it."""
    var full = len(data) // BLOCK_SIZE * BLOCK_SIZE
    for offset in range(0, full, BLOCK_SIZE):
        var block = data[offset : offset + BLOCK_SIZE]
        var ks = load_bytes[dtype=DType.uint8, width=BLOCK_SIZE](
            keystream[offset : offset + BLOCK_SIZE]
        )
        var s = load_bytes[dtype=DType.uint8, width=BLOCK_SIZE](block)
        store_bytes(block, s ^ ks)

    # Trailing partial block — CTR is a stream cipher, so only the bytes that
    # exist are XOR'd. A vector load would run off the end of `data`, so this
    # tail stays byte-wise.
    for j in range(full, len(data)):
        data[j] ^= keystream[j]
