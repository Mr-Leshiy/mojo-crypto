from .naive import _permute as naive_permute
from .common import _Keccak, _Sha3

# FIPS 202 §6.1 — SHA-3 domain-separation suffix (the bits '01' plus the
# `pad10*1` start bit, byte-aligned).
comptime SHA3_DOMAIN_SUFFIX: UInt8 = 0x06
# FIPS 202 §6.2 — SHAKE domain-separation suffix (the bits '1111' plus the
# `pad10*1` start bit, byte-aligned).
comptime SHAKE_DOMAIN_SUFFIX: UInt8 = 0x1F

comptime Sha3_224Naive = _Sha3[
    BlockSize=144,
    OutputSize=28,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-224 (FIPS 202 §6.1)."""

comptime Sha3_256Naive = _Sha3[
    BlockSize=136,
    OutputSize=32,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-256 (FIPS 202 §6.1)."""

comptime Sha3_384Naive = _Sha3[
    BlockSize=104,
    OutputSize=48,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-384 (FIPS 202 §6.1)."""

comptime Sha3_512Naive = _Sha3[
    BlockSize=72,
    OutputSize=64,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-512 (FIPS 202 §6.1)."""

comptime Shake128Naive = _Keccak[
    BlockSize=168, DomainSuffix=SHAKE_DOMAIN_SUFFIX, naive_permute
]
"""SHAKE128, an extendable-output function (FIPS 202 §6.2)."""

comptime Shake256Naive = _Keccak[
    BlockSize=136, DomainSuffix=SHAKE_DOMAIN_SUFFIX, naive_permute
]
"""SHAKE256, an extendable-output function (FIPS 202 §6.2)."""
