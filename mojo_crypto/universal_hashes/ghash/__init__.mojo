from mojo_crypto.universal_hashes.polyval import (
    PolyvalNaive,
    PolyvalAarch64,
    PolyvalX86,
)
from .generic import _GHashGeneric

comptime GHashNaive = _GHashGeneric[PolyvalNaive]
"""GHASH backed by the portable CPU POLYVAL implementation."""

comptime GHashAarch64 = _GHashGeneric[PolyvalAarch64]
"""GHASH backed by the ARMv8 PMULL-accelerated POLYVAL implementation."""

comptime GHashX86 = _GHashGeneric[PolyvalX86]
"""GHASH backed by the x86 PCLMULQDQ-accelerated POLYVAL implementation."""
