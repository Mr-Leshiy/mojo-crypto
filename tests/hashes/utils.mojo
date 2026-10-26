from mojo_crypto.hashes.traits import Digest, Xof

comptime DigestEngine = Digest & Movable & Deinitable
"""Bound every SHA-2/SHA-3 backend satisfies, and the one `check` is generic
over."""

comptime XofEngine = Xof & Movable & Deinitable
"""Bound every SHAKE backend satisfies, and the one `check` is generic over."""
