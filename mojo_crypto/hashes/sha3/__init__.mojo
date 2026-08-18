from .naive import _permute as naive_permute
from .common import _Keccak, _Sha3

# FIPS 202 §6.1/§6.2 — rate (sponge block size) in bytes for each algorithm;
# rate = 200 - 2 * (security strength in bytes).
comptime SHA3_224_RATE: Int = 144
comptime SHA3_256_RATE: Int = 136
comptime SHA3_384_RATE: Int = 104
comptime SHA3_512_RATE: Int = 72
comptime SHAKE128_RATE: Int = 168
comptime SHAKE256_RATE: Int = 136

# FIPS 202 §6.1 — SHA-3 domain-separation suffix (the bits '01' plus the
# `pad10*1` start bit, byte-aligned).
comptime SHA3_DOMAIN_SUFFIX: UInt8 = 0x06
# FIPS 202 §6.2 — SHAKE domain-separation suffix (the bits '1111' plus the
# `pad10*1` start bit, byte-aligned).
comptime SHAKE_DOMAIN_SUFFIX: UInt8 = 0x1F

comptime Sha3_224Naive = _Sha3[
    Rate=SHA3_224_RATE,
    OutputSize=28,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-224 (FIPS 202 §6.1)."""

comptime Sha3_256Naive = _Sha3[
    Rate=SHA3_256_RATE,
    OutputSize=32,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-256 (FIPS 202 §6.1)."""

comptime Sha3_384Naive = _Sha3[
    Rate=SHA3_384_RATE,
    OutputSize=48,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-384 (FIPS 202 §6.1)."""

comptime Sha3_512Naive = _Sha3[
    Rate=SHA3_512_RATE,
    OutputSize=64,
    DomainSuffix=SHA3_DOMAIN_SUFFIX,
    naive_permute,
]
"""SHA3-512 (FIPS 202 §6.1)."""

comptime Shake128Naive = _Keccak[
    Rate=SHAKE128_RATE, DomainSuffix=SHAKE_DOMAIN_SUFFIX, naive_permute
]
"""SHAKE128, an extendable-output function (FIPS 202 §6.2)."""

comptime Shake256Naive = _Keccak[
    Rate=SHAKE256_RATE, DomainSuffix=SHAKE_DOMAIN_SUFFIX, naive_permute
]
"""SHAKE256, an extendable-output function (FIPS 202 §6.2)."""
