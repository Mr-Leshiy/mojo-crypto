from .common import KECCAK_LANES, KECCAK_ROUNDS, RC, RHO


@always_inline
def _rotl(x: UInt64, n: UInt64) -> UInt64:
    # `(64 - n) & 63` rather than `64 - n` so that `n == 0` (the (0, 0) lane,
    # whose ρ offset is 0) doesn't shift by 64, which is undefined: it folds
    # to `x >> 0`, making the whole expression `x | x`.
    return (x << n) | (x >> ((64 - n) & 63))


# FIPS 202 §3.3 — one round of the Keccak-f[1600] permutation: θ, ρ, π, χ,
# then ι with the round's constant.
def _round(
    mut a: Array[UInt64, KECCAK_LANES],
    rho: Array[UInt64, KECCAK_LANES],
    rc: UInt64,
):
    # θ: XOR each lane with the parity of the two neighboring columns.
    var c = Array[UInt64, 5](uninitialized=True)
    for x in range(5):
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]

    var d = Array[UInt64, 5](uninitialized=True)
    for x in range(5):
        d[x] = c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1)

    for x in range(5):
        for y in range(5):
            a[x + 5 * y] ^= d[x]

    # ρ and π: rotate each lane, then move it to its transposed position.
    var b = Array[UInt64, KECCAK_LANES](uninitialized=True)
    for x in range(5):
        for y in range(5):
            var new_x = y
            var new_y = (2 * x + 3 * y) % 5
            b[new_x + 5 * new_y] = _rotl(a[x + 5 * y], rho[x + 5 * y])

    # χ: non-linear mix within each row.
    for x in range(5):
        for y in range(5):
            a[x + 5 * y] = b[x + 5 * y] ^ (
                (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]
            )

    # ι: break the round's symmetry with the round constant.
    a[0] ^= rc


# FIPS 202 §3.3 — the naive, portable Keccak-f[1600] permutation: 24 rounds
# of `_round`, each lane handled as a plain scalar.
def _permute(mut state: Array[UInt64, KECCAK_LANES]):
    var rc = materialize[RC]()
    var rho = materialize[RHO]()
    for round in range(KECCAK_ROUNDS):
        _round(state, rho, rc[round])
