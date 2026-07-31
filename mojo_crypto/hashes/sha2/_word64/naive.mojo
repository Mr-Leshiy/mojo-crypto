from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be
from .common import K64, ROUNDS_64, SHA2_WORD64_BLOCK_SIZE


# FIPS 180-4 §4.1.3 — rotate/shift amounts for the message-schedule sigma
# functions (σ0, σ1) and the compression-round sigma functions (Σ0, Σ1).
comptime SIGMA0_ROT_A: UInt64 = 1
comptime SIGMA0_ROT_B: UInt64 = 8
comptime SIGMA0_SHR: UInt64 = 7

comptime SIGMA1_ROT_A: UInt64 = 19
comptime SIGMA1_ROT_B: UInt64 = 61
comptime SIGMA1_SHR: UInt64 = 6

comptime BIG_SIGMA0_ROT_A: UInt64 = 28
comptime BIG_SIGMA0_ROT_B: UInt64 = 34
comptime BIG_SIGMA0_ROT_C: UInt64 = 39

comptime BIG_SIGMA1_ROT_A: UInt64 = 14
comptime BIG_SIGMA1_ROT_B: UInt64 = 18
comptime BIG_SIGMA1_ROT_C: UInt64 = 41


# FIPS 180-4 §6.4.2 — the SHA-512 compression function (also used by
# SHA-384, SHA-512/224, and SHA-512/256).
def _compress(
    mut state: SIMD[DType.uint64, 8],
    block: InlineArray[UInt8, SHA2_WORD64_BLOCK_SIZE],
):
    var block_span = Span(block)
    var w = InlineArray[UInt64, ROUNDS_64](uninitialized=True)
    for t in range(16):
        w[t] = load_be[DType.uint64](block_span[8 * t : 8 * t + 8])
    for t in range(16, ROUNDS_64):
        var s0 = (
            _rotr(w[t - 15], SIGMA0_ROT_A)
            ^ _rotr(w[t - 15], SIGMA0_ROT_B)
            ^ (w[t - 15] >> SIGMA0_SHR)
        )
        var s1 = (
            _rotr(w[t - 2], SIGMA1_ROT_A)
            ^ _rotr(w[t - 2], SIGMA1_ROT_B)
            ^ (w[t - 2] >> SIGMA1_SHR)
        )
        w[t] = w[t - 16] + s0 + w[t - 7] + s1

    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]

    for t in range(ROUNDS_64):
        var s1 = (
            _rotr(e, BIG_SIGMA1_ROT_A)
            ^ _rotr(e, BIG_SIGMA1_ROT_B)
            ^ _rotr(e, BIG_SIGMA1_ROT_C)
        )
        var ch = (e & f) ^ (~e & g)
        var temp1 = h + s1 + ch + K64[t] + w[t]
        var s0 = (
            _rotr(a, BIG_SIGMA0_ROT_A)
            ^ _rotr(a, BIG_SIGMA0_ROT_B)
            ^ _rotr(a, BIG_SIGMA0_ROT_C)
        )
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h


@always_inline
def _rotr(x: UInt64, n: UInt64) -> UInt64:
    return (x >> n) | (x << (64 - n))
