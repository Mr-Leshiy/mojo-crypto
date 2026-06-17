from mojo_crypto.universal_hashes.polyval import (
    PolyvalCpu,
    PolyvalAarch64,
    PolyvalX86,
)
from .generic import GHashGeneric

comptime GHashCpu = GHashGeneric[PolyvalCpu]
comptime GHashAarch64 = GHashGeneric[PolyvalAarch64]
comptime GHashX86 = GHashGeneric[PolyvalX86]
