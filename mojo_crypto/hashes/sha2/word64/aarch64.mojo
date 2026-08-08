# SHA-2 (64-bit word) via the ARMv8.2 SHA-512 Crypto Extension.
#
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td

from std.sys.intrinsics import llvm_intrinsic

from .common import K64, SHA2_WORD64_BLOCK_SIZE

# Every SHA-512 crypto instruction operates on two 64-bit words at a time —
# the `v2i64` of the LLVM signatures, i.e. one 128-bit register. The state is
# carried as four such pairs (ab, cd, ef, gh) and the schedule as eight.
comptime Words = SIMD[DType.uint64, 2]


# FIPS 180-4 §6.4.2 — the SHA-512 compression function,
# via the ARMv8.2 SHA-512 Crypto Extension.
def _compress(
    mut state: SIMD[DType.uint64, 8],
    block: Array[UInt8, SHA2_WORD64_BLOCK_SIZE],
):
    var ab = state.slice[2]()
    var cd = state.slice[2, offset=2]()
    var ef = state.slice[2, offset=4]()
    var gh = state.slice[2, offset=6]()

    # FIPS 180-4 §6.4.2 step 1 — the first 16 message-schedule words, two to a
    # vector. `big_endian=True` does the byte-order work of `vrev64q_u8`: the
    # block is big-endian on the wire, and each word is swapped into the
    # host's native order on the way in.
    var w = SIMD[DType.uint64, 16].from_bytes[big_endian=True](block)
    var s0 = w.slice[2]()
    var s1 = w.slice[2, offset=2]()
    var s2 = w.slice[2, offset=4]()
    var s3 = w.slice[2, offset=6]()
    var s4 = w.slice[2, offset=8]()
    var s5 = w.slice[2, offset=10]()
    var s6 = w.slice[2, offset=12]()
    var s7 = w.slice[2, offset=14]()

    # Rounds 0-15 consume the schedule as loaded. Each call advances two
    # rounds and rotates which state vectors it reads and updates, so the four
    # arguments cycle through (ab, cd, ef, gh) one position at a time.
    _round[0](ab, cd, ef, gh, s0)
    _round[2](gh, ab, cd, ef, s1)
    _round[4](ef, gh, ab, cd, s2)
    _round[6](cd, ef, gh, ab, s3)
    _round[8](ab, cd, ef, gh, s4)
    _round[10](gh, ab, cd, ef, s5)
    _round[12](ef, gh, ab, cd, s6)
    _round[14](cd, ef, gh, ab, s7)

    # Rounds 16-79. FIPS 180-4 §6.4.2 step 1 defines W[t] for t >= 16 in terms
    # of W[t-16], W[t-15], W[t-7] and W[t-2]; sha512su0/sha512su1 compute two
    # of those at once, so each group rewrites the oldest vector in place and
    # the eight vectors rotate through the roles.
    comptime for t in range(16, 80, 16):
        s0 = _sha512su1(_sha512su0(s0, s1), s7, _ext(s4, s5))
        _round[t](ab, cd, ef, gh, s0)

        s1 = _sha512su1(_sha512su0(s1, s2), s0, _ext(s5, s6))
        _round[t + 2](gh, ab, cd, ef, s1)

        s2 = _sha512su1(_sha512su0(s2, s3), s1, _ext(s6, s7))
        _round[t + 4](ef, gh, ab, cd, s2)

        s3 = _sha512su1(_sha512su0(s3, s4), s2, _ext(s7, s0))
        _round[t + 6](cd, ef, gh, ab, s3)

        s4 = _sha512su1(_sha512su0(s4, s5), s3, _ext(s0, s1))
        _round[t + 8](ab, cd, ef, gh, s4)

        s5 = _sha512su1(_sha512su0(s5, s6), s4, _ext(s1, s2))
        _round[t + 10](gh, ab, cd, ef, s5)

        s6 = _sha512su1(_sha512su0(s6, s7), s5, _ext(s2, s3))
        _round[t + 12](ef, gh, ab, cd, s6)

        s7 = _sha512su1(_sha512su0(s7, s0), s6, _ext(s3, s4))
        _round[t + 14](cd, ef, gh, ab, s7)

    # FIPS 180-4 §6.4.2 step 4 — add the working vectors back into the state.
    # `state` is still the value the rounds started from, so it doubles as the
    # `*_orig` copies the C implementations keep by hand.
    state += ab.join(cd).join(ef.join(gh))


# One group of two rounds, starting at round `first`.
#
# The state pairs arrive in rotated order rather than by name: `z` holds the
# two words the round consumes, and `x` and `z` are the two it updates.
# Successive calls shift the rotation by one, which is what lets all forty
# groups share this body.
@always_inline
def _round[
    first: Int
](w: Words, mut x: Words, y: Words, mut z: Words, schedule: Words):
    var initial_sum = schedule + comptime (Words(K64[first], K64[first + 1]))
    var sum = _ext(initial_sum, initial_sum) + z
    var intermed = _sha512h(sum, _ext(y, z), _ext(x, y))
    z = _sha512h2(intermed, x, w)
    x += intermed


# `vextq_u64(a, b, 1)` — the high word of `a` followed by the low word of `b`.
# In a two-vector shuffle mask, lanes 0-1 index `self` and lanes 2-3 `other`.
@always_inline
def _ext(a: Words, b: Words) -> Words:
    return a.shuffle[1, 2](b)


# SHA512H: the Sigma1/choose half of two rounds.
@always_inline
def _sha512h(sum: Words, yz: Words, xy: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha512h", Words](sum, yz, xy)


# SHA512H2: the Sigma0/majority half of the same two rounds.
@always_inline
def _sha512h2(intermed: Words, x: Words, w: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha512h2", Words](intermed, x, w)


# SHA512SU0: the first half of the message-schedule update — the sigma0 term
# over W[t-15], applied to W[t-16..t-14].
@always_inline
def _sha512su0(w0_1: Words, w2_3: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha512su0", Words](w0_1, w2_3)


# SHA512SU1: the second half — the sigma1 term over W[t-2] plus W[t-7],
# applied to the partial result from sha512su0.
@always_inline
def _sha512su1(partial: Words, w7: Words, w2: Words) -> Words:
    return llvm_intrinsic["llvm.aarch64.crypto.sha512su1", Words](
        partial, w7, w2
    )
