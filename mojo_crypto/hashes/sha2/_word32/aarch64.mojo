# SHA-2 (32-bit word) via the ARMv8 SHA-256 Crypto Extension.
#
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td

from std.sys.intrinsics import llvm_intrinsic

from .common import K32, SHA2_WORD32_BLOCK_SIZE

# Every SHA-256 crypto instruction operates on four 32-bit words at a time
comptime Words = SIMD[DType.uint32, 4]


# FIPS 180-4 §6.2.2 — the SHA-256 compression function,
# via the ARMv8 SHA-256 Crypto Extension.
def _compress(
    mut state: SIMD[DType.uint32, 8],
    block: InlineArray[UInt8, SHA2_WORD32_BLOCK_SIZE],
):
    var abcd = state.slice[4]()
    var efgh = state.slice[4, offset=4]()

    # FIPS 180-4 §6.2.2 step 1 — the first 16 message-schedule words, split
    # into the four vectors sha256su0/sha256su1 operate on. `big_endian=True`
    # does the byte-order work of `vrev32q_u8`: the block is big-endian on the
    # wire, and each word is swapped into the host's native order on the way in.
    var w = SIMD[DType.uint32, 16].from_bytes[big_endian=True](block)
    var s0 = w.slice[4]()
    var s1 = w.slice[4, offset=4]()
    var s2 = w.slice[4, offset=8]()
    var s3 = w.slice[4, offset=12]()

    # Rounds 0-15 consume the schedule as loaded.
    _rounds[0](abcd, efgh, s0)
    _rounds[4](abcd, efgh, s1)
    _rounds[8](abcd, efgh, s2)
    _rounds[12](abcd, efgh, s3)

    # Rounds 16-63. FIPS 180-4 §6.2.2 step 1 defines W[t] for t >= 16 in terms
    # of W[t-16], W[t-15], W[t-7] and W[t-2]; sha256su0/sha256su1 compute four
    # of those at once, so each group rewrites the oldest vector in place and
    # the four vectors rotate through the roles.
    comptime for t in range(16, 64, 16):
        s0 = _sha256su1(_sha256su0(s0, s1), s2, s3)
        _rounds[t](abcd, efgh, s0)

        s1 = _sha256su1(_sha256su0(s1, s2), s3, s0)
        _rounds[t + 4](abcd, efgh, s1)

        s2 = _sha256su1(_sha256su0(s2, s3), s0, s1)
        _rounds[t + 8](abcd, efgh, s2)

        s3 = _sha256su1(_sha256su0(s3, s0), s1, s2)
        _rounds[t + 12](abcd, efgh, s3)

    # FIPS 180-4 §6.2.2 step 4 — add the working vectors back into the state.
    # `state` is still the value the rounds started from, so it doubles as the
    # `abcd_orig`/`efgh_orig` the C implementations keep by hand.
    state += abcd.join(efgh)


@always_inline
def _rounds[first: Int](mut abcd: Words, mut efgh: Words, schedule: Words):
    var wk = schedule + Words(
        K32[first], K32[first + 1], K32[first + 2], K32[first + 3]
    )
    abcd, efgh = _sha256h(abcd, efgh, wk), _sha256h2(efgh, abcd, wk)


@always_inline
def _sha256h(abcd: Words, efgh: Words, wk: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h", Words](abcd, efgh, wk)


@always_inline
def _sha256h2(efgh: Words, abcd: Words, wk: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h2", Words](efgh, abcd, wk)


@always_inline
def _sha256su0(w0_3: Words, w4_7: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su0", Words](w0_3, w4_7)


@always_inline
def _sha256su1(partial: Words, w8_11: Words, w12_15: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su1", Words](
        partial, w8_11, w12_15
    )
