# SHA-2 (32-bit word) via the x86 SHA-NI extension (`+sha`).
#
# LLVM x86 intrinsic definitions (.td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsX86.td
# Intel intrinsics guide:
#   https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=sha256

from std.sys.intrinsics import llvm_intrinsic

from .common import K32, SHA2_WORD32_BLOCK_SIZE

# Every SHA-NI instruction operates on four 32-bit words at a time — the
# `v4i32` of the LLVM signatures, i.e. one 128-bit XMM register. Lane 0 is the
# least significant word, so lane `i` is Intel's `dst[32*i+31 : 32*i]`.
comptime Words = SIMD[DType.uint32, 4]


# FIPS 180-4 §6.2.2 — the SHA-256 compression function,
# via the x86 SHA-NI extension.
def _compress(
    mut state: SIMD[DType.uint32, 8],
    block: InlineArray[UInt8, SHA2_WORD32_BLOCK_SIZE],
):
    # SHA256RNDS2 carries the state as two interleaved quarters rather than as
    # A..D / E..H, so re-lane it once here and undo that after the rounds.
    var abcd = state.slice[4]()
    var efgh = state.slice[4, offset=4]()
    var abef = abcd.shuffle[5, 4, 1, 0](efgh)
    var cdgh = abcd.shuffle[7, 6, 3, 2](efgh)

    # FIPS 180-4 §6.2.2 step 1 — the first 16 message-schedule words, split
    # into the four vectors sha256msg1/sha256msg2 operate on. `big_endian=True`
    # does the byte-order work of the `_mm_shuffle_epi8` swap mask: the block is
    # big-endian on the wire, and each word is swapped into the host's native
    # order on the way in.
    var w = SIMD[DType.uint32, 16].from_bytes[big_endian=True](block)
    var s0 = w.slice[4]()
    var s1 = w.slice[4, offset=4]()
    var s2 = w.slice[4, offset=8]()
    var s3 = w.slice[4, offset=12]()

    # Rounds 0-15 consume the schedule as loaded.
    _rounds[0](abef, cdgh, s0)
    _rounds[4](abef, cdgh, s1)
    _rounds[8](abef, cdgh, s2)
    _rounds[12](abef, cdgh, s3)

    # Rounds 16-63. FIPS 180-4 §6.2.2 step 1 defines W[t] for t >= 16 in terms
    # of W[t-16], W[t-15], W[t-7] and W[t-2]; sha256msg1/sha256msg2 compute four
    # of those at once, so each group rewrites the oldest vector in place and
    # the four vectors rotate through the roles.
    comptime for t in range(16, 64, 16):
        s0 = _sha256msg2(_sha256msg1(s0, s1) + _ext(s2, s3), s3)
        _rounds[t](abef, cdgh, s0)

        s1 = _sha256msg2(_sha256msg1(s1, s2) + _ext(s3, s0), s0)
        _rounds[t + 4](abef, cdgh, s1)

        s2 = _sha256msg2(_sha256msg1(s2, s3) + _ext(s0, s1), s1)
        _rounds[t + 8](abef, cdgh, s2)

        s3 = _sha256msg2(_sha256msg1(s3, s0) + _ext(s1, s2), s2)
        _rounds[t + 12](abef, cdgh, s3)

    # FIPS 180-4 §6.2.2 step 4 — un-interleave back into A..H and add into the
    # state, which is still the value the rounds started from and so doubles as
    # the `*_SAVE` copies the C implementations keep by hand.
    state += abef.shuffle[3, 2, 7, 6](cdgh).join(abef.shuffle[1, 0, 5, 4](cdgh))


# One group of four rounds, starting at round `first`.
#
# SHA256RNDS2 advances two rounds and reads only lanes 0-1 of `wk`, so each
# schedule vector drives two calls, the second fed lanes 2-3 rotated down
# (`_mm_shuffle_epi32(MSG, 0x0E)`). Two rounds turn the incoming `abef` into
# the new `cdgh`, hence the rotate rather than a plain assignment.
@always_inline
def _rounds[first: Int](mut abef: Words, mut cdgh: Words, schedule: Words):
    var wk = schedule + Words(
        K32[first], K32[first + 1], K32[first + 2], K32[first + 3]
    )
    abef, cdgh = _sha256rnds2(cdgh, abef, wk), abef

    var wk_hi = wk.shuffle[2, 3, 0, 1](wk)
    abef, cdgh = _sha256rnds2(cdgh, abef, wk_hi), abef


# SHA256RNDS2: two full rounds, `wk` holding W[t]+K[t] and W[t+1]+K[t+1] in
# lanes 0-1. State is split as abef = (F, E, B, A) and cdgh = (H, G, D, C) in
# lanes 0-3; the result is the new abef.
@always_inline
def _sha256rnds2(cdgh: Words, abef: Words, wk: Words) -> Words:
    return llvm_intrinsic["llvm.x86.sha256rnds2", Words](cdgh, abef, wk)


# SHA256MSG1: the sigma0 half of the message-schedule update — lane `i` is
# W[t-16+i] + sigma0(W[t-15+i]), taking only lane 0 of `w4_7`. Equivalent to
# AArch64's SHA256SU0.
@always_inline
def _sha256msg1(w0_3: Words, w4_7: Words) -> Words:
    return llvm_intrinsic["llvm.x86.sha256msg1", Words](w0_3, w4_7)


# SHA256MSG2: the sigma1 half, completing W[t..t+3] from W[t-2] and W[t-1] in
# lanes 2-3 of `w12_15`. Unlike AArch64's SHA256SU1 the W[t-7..t-4] term is not
# folded in, so the caller must already have added it into `partial`.
@always_inline
def _sha256msg2(partial: Words, w12_15: Words) -> Words:
    return llvm_intrinsic["llvm.x86.sha256msg2", Words](partial, w12_15)


# `_mm_alignr_epi8(b, a, 4)` — lanes 1-3 of `a` then lane 0 of `b`, gathering
# the W[t-7..t-4] addend that straddles two schedule vectors. In a two-vector
# shuffle mask, lanes 0-3 index `a` and lanes 4-7 index `b`.
@always_inline
def _ext(a: Words, b: Words) -> Words:
    return a.shuffle[1, 2, 3, 4](b)
