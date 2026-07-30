from .naive import _Sha2Naive32

comptime Sha224Naive = _Sha2Naive32[
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
    28,
]
"""SHA-224 (FIPS 180-4 §5.3.2 initial hash value)."""

comptime Sha256Naive = _Sha2Naive32[
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
    32,
]
"""SHA-256 (FIPS 180-4 §5.3.3 initial hash value)."""
