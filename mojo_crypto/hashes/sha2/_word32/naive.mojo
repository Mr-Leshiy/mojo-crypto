from std.memory import unsafe_memcpy
from std.math import min

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.utils import load_be
from .common import K32, ROUNDS_32, SHA2_WORD32_BLOCK_SIZE

# FIPS 180-4 §4.1.2 — rotate/shift amounts for the message-schedule sigma
# functions (σ0, σ1) and the compression-round sigma functions (Σ0, Σ1).
comptime SIGMA0_ROT_A: UInt32 = 7
comptime SIGMA0_ROT_B: UInt32 = 18
comptime SIGMA0_SHR: UInt32 = 3

comptime SIGMA1_ROT_A: UInt32 = 17
comptime SIGMA1_ROT_B: UInt32 = 19
comptime SIGMA1_SHR: UInt32 = 10

comptime BIG_SIGMA0_ROT_A: UInt32 = 2
comptime BIG_SIGMA0_ROT_B: UInt32 = 13
comptime BIG_SIGMA0_ROT_C: UInt32 = 22

comptime BIG_SIGMA1_ROT_A: UInt32 = 6
comptime BIG_SIGMA1_ROT_B: UInt32 = 11
comptime BIG_SIGMA1_ROT_C: UInt32 = 25


# FIPS 180-4 §6.2.2 — the SHA-256 compression function (also used by SHA-224).
def _compress(
    mut state: SIMD[DType.uint32, 8],
    block: InlineArray[UInt8, SHA2_WORD32_BLOCK_SIZE],
):
    var block_span = Span(block)
    var w = InlineArray[UInt32, ROUNDS_32](uninitialized=True)
    for t in range(16):
        w[t] = load_be[DType.uint32](block_span[4 * t : 4 * t + 4])
    for t in range(16, ROUNDS_32):
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

    for t in range(ROUNDS_32):
        var s1 = (
            _rotr(e, BIG_SIGMA1_ROT_A)
            ^ _rotr(e, BIG_SIGMA1_ROT_B)
            ^ _rotr(e, BIG_SIGMA1_ROT_C)
        )
        var ch = (e & f) ^ (~e & g)
        var temp1 = h + s1 + ch + K32[t] + w[t]
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
def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (32 - n))
