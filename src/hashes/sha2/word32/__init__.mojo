from .naive import _compress as naive_compress
from .aarch64 import _compress as aarch64_compress
from .x86 import _compress as x86_compress
from .common import SHA224_IV, SHA256_IV, _Sha2Word32

comptime Sha224Naive = _Sha2Word32[SHA224_IV, 28, naive_compress]
"""SHA-224 (FIPS 180-4 §5.3.2 initial hash value)."""

comptime Sha256Naive = _Sha2Word32[SHA256_IV, 32, naive_compress]
"""SHA-256 (FIPS 180-4 §5.3.3 initial hash value)."""

comptime Sha224Aarch64 = _Sha2Word32[SHA224_IV, 28, aarch64_compress]
"""SHA-224 via the ARMv8 SHA-256 Crypto Extension."""

comptime Sha256Aarch64 = _Sha2Word32[SHA256_IV, 32, aarch64_compress]
"""SHA-256 via the ARMv8 SHA-256 Crypto Extension."""

comptime Sha224X86 = _Sha2Word32[SHA224_IV, 28, x86_compress]
"""SHA-224 via the x86 SHA-NI extension."""

comptime Sha256X86 = _Sha2Word32[SHA256_IV, 32, x86_compress]
"""SHA-256 via the x86 SHA-NI extension."""
