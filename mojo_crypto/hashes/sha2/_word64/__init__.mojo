from .naive import _compress as naive_compress
from .aarch64 import _compress as aarch64_compress
from .common import (
    SHA384_IV,
    SHA512_IV,
    SHA512_224_IV,
    SHA512_256_IV,
    _Sha2Word64,
)

comptime Sha384Naive = _Sha2Word64[SHA384_IV, 48, naive_compress]
"""SHA-384 (FIPS 180-4 §5.3.4 initial hash value)."""

comptime Sha512Naive = _Sha2Word64[SHA512_IV, 64, naive_compress]
"""SHA-512 (FIPS 180-4 §5.3.5 initial hash value)."""

comptime Sha512_224Naive = _Sha2Word64[SHA512_224_IV, 28, naive_compress]
"""SHA-512/224 (FIPS 180-4 §5.3.6.1 initial hash value)."""

comptime Sha512_256Naive = _Sha2Word64[SHA512_256_IV, 32, naive_compress]
"""SHA-512/256 (FIPS 180-4 §5.3.6.2 initial hash value)."""

comptime Sha384Aarch64 = _Sha2Word64[SHA384_IV, 48, aarch64_compress]
"""SHA-384 via the ARMv8.2 SHA-512 Crypto Extension."""

comptime Sha512Aarch64 = _Sha2Word64[SHA512_IV, 64, aarch64_compress]
"""SHA-512 via the ARMv8.2 SHA-512 Crypto Extension."""

comptime Sha512_224Aarch64 = _Sha2Word64[SHA512_224_IV, 28, aarch64_compress]
"""SHA-512/224 via the ARMv8.2 SHA-512 Crypto Extension."""

comptime Sha512_256Aarch64 = _Sha2Word64[SHA512_256_IV, 32, aarch64_compress]
"""SHA-512/256 via the ARMv8.2 SHA-512 Crypto Extension."""
