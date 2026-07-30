from .naive import _compress as naive_compress
from .common import SHA224_IV, SHA256_IV, _Sha2Word32

comptime Sha224Naive = _Sha2Word32[SHA224_IV, 28, naive_compress]
"""SHA-224 (FIPS 180-4 §5.3.2 initial hash value)."""

comptime Sha256Naive = _Sha2Word32[SHA256_IV, 32, naive_compress]
"""SHA-256 (FIPS 180-4 §5.3.3 initial hash value)."""
