from std.memory import unsafe_memcpy

from mojo_crypto.hashes.traits import Digest
from mojo_crypto.macs.traits import Mac


struct Hmac[H: Digest & Movable & ImplicitlyDeletable](
    ImplicitlyDeletable, Mac, Movable
):
    """
    **HMAC**: a hash-based message authentication code.

    HMAC turns any Merkle-Damgard hash into a MAC by nesting two hash calls
    around the message:

        HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m))

    The outer call is what closes the length-extension forgery that a bare
    `H(key || message)` admits.

    `K0` is the key resized to exactly one hash block: hashed down first if it
    is longer than a block, then zero-padded on the right.

    FIPS 198-1:
    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
    RFC 2104:
    https://datatracker.ietf.org/doc/html/rfc2104
    """

    comptime BLOCK_SIZE: Int = Self.H.BLOCK_SIZE
    comptime TAG_SIZE: Int = Self.H.OUTPUT_SIZE

    comptime IPAD = SIMD[DType.uint8, Self.BLOCK_SIZE](0x36)
    """FIPS 198-1 §4 — the inner pad byte, splatted across a whole block."""

    comptime OPAD = SIMD[DType.uint8, Self.BLOCK_SIZE](0x5C)
    """FIPS 198-1 §4 — the outer pad byte, splatted across a whole block."""

    var _inner: Self.H
    """The inner hash, primed with `K0 ^ ipad`; absorbs the message itself."""

    var _k0: SIMD[DType.uint8, Self.BLOCK_SIZE]
    """
    `K0`, the block-sized key.
    """

    def __init__[o: Origin](out self, key: Span[UInt8, o]):
        """
        Initialize HMAC from a key of any length.

        Derives `K0` (FIPS 198-1 §4 steps 1-3) and primes the inner hash with
        `K0 ^ ipad` (step 4-5), leaving it ready to absorb the message.
        """
        self._k0 = _k0[Self.BLOCK_SIZE, H = Self.H](key)
        self._inner = Self.H()
        self._inner.update(Span(Self._padded_key(self._k0, Self.IPAD)))

    def update[o: Origin](mut self, data: Span[UInt8, o]) raises:
        """Absorb more input."""
        # Step 6, `(K0 ^ ipad) || text`. HMAC adds no buffering of its own:
        # `K0 ^ ipad` is exactly one block, so the message follows it at a
        # block boundary and the inner hash's own buffer handles the rest.
        self._inner.update(data)

    def finalize(var self) raises -> InlineArray[UInt8, Self.TAG_SIZE]:
        """
        Consume self and return the TAG_SIZE-byte authentication tag.

        Closes the inner hash over `(K0 ^ ipad) || text` (FIPS 198-1 §4
        step 7), then runs a fresh outer hash over
        `(K0 ^ opad) || H((K0 ^ ipad) || text)` (steps 8-9).
        """
        var outer_block = Self._padded_key(self._k0, Self.OPAD)

        # `Digest.finalize` consumes its hash, so the inner hash has to be
        # moved out of `self`. Mojo rejects a partial move out of a `var self`
        # whose remaining fields still need destroying, hence the fresh hash
        # put back in its place.
        var inner = self._inner^
        self._inner = Self.H()
        var inner_digest = inner^.finalize()

        var outer = Self.H()
        outer.update(Span(outer_block))
        outer.update(Span(inner_digest))
        return outer^.finalize()

    def reset(mut self):
        """
        Reset the accumulator to its initial state while keeping the key.

        Restores the inner hash to the just-absorbed-`K0 ^ ipad` state, so
        another message can be authenticated under the same key without
        re-deriving `K0`.
        """
        self._inner.reset()
        self._inner.update(Span(Self._padded_key(self._k0, Self.IPAD)))

    @staticmethod
    def _padded_key(
        k0: SIMD[DType.uint8, Self.BLOCK_SIZE],
        pad: SIMD[DType.uint8, Self.BLOCK_SIZE],
    ) -> InlineArray[UInt8, Self.BLOCK_SIZE]:
        """`K0 ^ pad` as a byte block, ready to feed to a hash."""
        var block = InlineArray[UInt8, Self.BLOCK_SIZE](uninitialized=True)
        UnsafePointer(block.unsafe_ptr()).store[alignment=1](k0 ^ pad)
        return block^


def _k0[
    size: Int, o: Origin, H: Digest
](key: Span[UInt8, o]) -> SIMD[DType.uint8, size]:
    """
    Resize a key of any length to exactly `size` bytes — FIPS 198-1 §3.

    HMAC XORs the key against a full hash block, so a key that is not already
    block-sized has to be stretched or shrunk to fit:

    - longer than `size`: hashed down to an `OUTPUT_SIZE`-byte string, then
      right-padded with zeros (step 3, `K0 = H(K) || 00...00`);
    - `size` or shorter: taken as-is and right-padded with zeros (steps 1-2,
      `K0 = K || 00...00`, a no-op when the key is already `size` bytes).

    Both branches leave the tail zero for free — `k0` starts zero-filled, so
    only the leading bytes are ever written. The result is returned as a
    vector, ready to be XORed with a splatted `ipad`/`opad` byte.

    Note that hashing a long key discards the excess: any two keys with the
    same `H(K)` authenticate identically. That is inherent to the standard,
    not a shortcut taken here.
    """
    # Holds for every hash worth instantiating this over — a Merkle-Damgard
    # compression function that did not shrink its input would not compress —
    # but FIPS 198-1 leaves `H(K) || 00...00` undefined when it does not, and
    # the copy below would overrun `k0`.

    comptime assert (
        H.OUTPUT_SIZE <= size
    ), "digest is wider than K0; H(K) does not fit"

    var k0 = InlineArray[UInt8, size](fill=0)
    if len(key) > size:
        var h = H()
        h.update(key)
        var h_k = h^.finalize()
        unsafe_memcpy(
            dest=k0.unsafe_ptr(), src=h_k.unsafe_ptr(), count=len(h_k)
        )
    else:
        unsafe_memcpy(
            dest=k0.unsafe_ptr(), src=key.unsafe_ptr(), count=len(key)
        )

    return UnsafePointer(k0.unsafe_ptr()).load[width=size, alignment=1]()
