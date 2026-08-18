from std.math import min

from mojo_crypto.hashes.traits import Digest, Xof

comptime KECCAK_LANES: Int = 25
"""The Keccak-f[1600] state: a 5x5 matrix of 64-bit lanes, lane (x, y) at
index x + 5*y."""

comptime KECCAK_ROUNDS: Int = 24
"""FIPS 202 §3.3 — number of rounds in the Keccak-f[1600] permutation."""

# FIPS 202 §3.2.5 — round constants for the ι step, one per round of
# Keccak-f[1600] (Algorithm 1 / Table in Appendix B computes these; listed
# literally here as in the Keccak reference implementation).
comptime RC: Array[UInt64, KECCAK_ROUNDS] = [
    # fmt: off
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    # fmt: on
]

# FIPS 202 §3.2.2 — ρ step rotation offsets r[x, y], flattened at index
# x + 5*y.
comptime RHO: Array[UInt64, KECCAK_LANES] = [
    # fmt: off
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
    # fmt: on
]


struct _Keccak[
    permute: def(mut Array[UInt64, KECCAK_LANES]) thin,
    *,
    Rate: Int,
    DomainSuffix: UInt8,
](Copyable, Deinitable, Movable, Xof):
    """
    The Keccak sponge construction (FIPS 202 §4) underlying SHA-3 and SHAKE.

    `RATE` (the sponge's block size, in bytes) and `DomainSuffix` (the bits
    FIPS 202 §6.1/§6.2 append before the `pad10*1` padding — `0x06` for
    SHA-3, `0x1F` for SHAKE) are the only two knobs that separate the six
    algorithms; the absorb/permute/squeeze machinery is shared by all of
    them. `permute` selects the Keccak-f[1600] backend.
    """

    comptime BLOCK_SIZE: Int = Self.Rate

    var _state: Array[UInt64, KECCAK_LANES]
    var _buffer: Array[UInt8, Self.Rate]
    var _buffer_len: Int
    var _squeezing: Bool
    var _squeeze_pos: Int

    def __init__(out self):
        self._state = Array[UInt64, KECCAK_LANES](fill=0)
        self._buffer = Array[UInt8, Self.Rate](uninitialized=True)
        self._buffer_len = 0
        self._squeezing = False
        self._squeeze_pos = 0

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input."""
        debug_assert(
            not self._squeezing, "Keccak.update: already squeezing output"
        )
        var input = data

        # A prior `update` call left a partial block buffered — top it off
        # before deciding whether it is now full.
        if self._buffer_len > 0:
            var take = min(Self.Rate - self._buffer_len, len(input))
            self._buffer_span(take).copy_from(input[:take])
            self._buffer_len += take
            input = input[take:]
            if self._buffer_len == Self.Rate:
                self._absorb_block()
                self._buffer_len = 0

        while len(input) >= Self.Rate:
            Span(self._buffer).copy_from(input[: Self.Rate])
            self._absorb_block()
            input = input[Self.Rate :]

        if len(input) > 0:
            self._buffer_span(len(input)).copy_from(input)
            self._buffer_len += len(input)

    @always_inline
    def _buffer_span(
        mut self, count: Int
    ) -> Span[UInt8, origin_of(self._buffer)]:
        """The `count` free buffer bytes starting at the buffered prefix."""
        return Span(self._buffer)[self._buffer_len : self._buffer_len + count]

    def _absorb_block(mut self):
        """XOR the full `_buffer` into the state's leading `RATE` bytes and
        permute. Byte `i` of the state is lane `i // 8`'s byte `i % 8`,
        little-endian — FIPS 202 §3.1.2's bits-to-bytes-to-lanes mapping."""
        for i in range(Self.Rate):
            self._state[i // 8] ^= UInt64(self._buffer[i]) << UInt64(
                8 * (i % 8)
            )
        Self.permute(self._state)

    def _finish_absorb(mut self):
        """FIPS 202 §5.1 `pad10*1`: zero-fill the rest of the block, XOR in
        the domain-separation suffix where the message left off and the
        final `1` bit at the block's last byte, then absorb this last block
        and switch to squeezing."""
        for i in range(self._buffer_len, Self.Rate):
            self._buffer[i] = 0
        self._buffer[self._buffer_len] ^= Self.DomainSuffix
        self._buffer[Self.Rate - 1] ^= 0x80
        self._absorb_block()
        self._buffer_len = 0
        self._squeezing = True
        self._squeeze_pos = 0

    def squeeze[o: MutOrigin](mut self, data: Span[UInt8, o]):
        """Fill `data` with the next `len(data)` bytes of output."""
        if not self._squeezing:
            self._finish_absorb()

        var out = data
        while len(out) > 0:
            if self._squeeze_pos == Self.Rate:
                Self.permute(self._state)
                self._squeeze_pos = 0

            var take = min(Self.Rate - self._squeeze_pos, len(out))
            for i in range(take):
                var pos = self._squeeze_pos + i
                out[i] = UInt8(self._state[pos // 8] >> UInt64(8 * (pos % 8)))
            self._squeeze_pos += take
            out = out[take:]

    def reset(mut self):
        """Reset the sponge to its initial state."""
        self._state = Array[UInt64, KECCAK_LANES](fill=0)
        self._buffer_len = 0
        self._squeezing = False
        self._squeeze_pos = 0


struct _Sha3[
    permute: def(mut Array[UInt64, KECCAK_LANES]) thin,
    *,
    Rate: Int,
    OutputSize: Int,
    DomainSuffix: UInt8,
](Copyable, Deinitable, Digest, Movable):
    """
    A fixed-output SHA-3 instance: `_Keccak` squeezed exactly `DigestSize`
    bytes once, per FIPS 202 §6.1's SHA3-224/256/384/512.
    """

    comptime BLOCK_SIZE: Int = Self.Rate
    comptime OUTPUT_SIZE: Int = Self.OutputSize

    var _sponge: _Keccak[
        Rate=Self.Rate, DomainSuffix=Self.DomainSuffix, Self.permute
    ]

    def __init__(out self):
        self._sponge = _Keccak[
            Rate=Self.Rate, DomainSuffix=Self.DomainSuffix, Self.permute
        ]()

    def update[o: Origin](mut self, data: Span[UInt8, o]):
        """Absorb more input."""
        self._sponge.update(data)

    def finalize(var self) -> Array[UInt8, Self.OutputSize]:
        """Consume self and return the OUTPUT_SIZE-byte digest."""
        var out = Array[UInt8, Self.OutputSize](uninitialized=True)
        self._sponge.squeeze(Span(out))
        return out^

    def reset(mut self):
        """Reset the hash to its initial state."""
        self._sponge.reset()
