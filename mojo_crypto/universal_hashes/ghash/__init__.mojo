from mojo_crypto.universal_hashes.polyval import (
    PolyvalNaive,
    PolyvalAarch64,
    PolyvalX86,
)
from .generic import GHashGeneric

comptime GHashNaive = GHashGeneric[PolyvalNaive]
"""GHASH backed by the portable CPU POLYVAL implementation."""

comptime GHashAarch64 = GHashGeneric[PolyvalAarch64]
"""GHASH backed by the ARMv8 PMULL-accelerated POLYVAL implementation."""

comptime GHashX86 = GHashGeneric[PolyvalX86]
"""GHASH backed by the x86 PCLMULQDQ-accelerated POLYVAL implementation."""
