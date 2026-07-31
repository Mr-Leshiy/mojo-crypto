from .naive import AesNaive
from .aarch64 import AesAarch64
from .x86 import AesX86
from .gpu import AesGpu
from .common import BLOCK_SIZE

comptime Aes128Naive = AesNaive[16]
"""AES-128 using the portable CPU implementation."""

comptime Aes192Naive = AesNaive[24]
"""AES-192 using the portable CPU implementation."""

comptime Aes256Naive = AesNaive[32]
"""AES-256 using the portable CPU implementation."""

comptime Aes128Aarch64 = AesAarch64[16]
"""AES-128 using the ARMv8 Crypto Extension implementation."""

comptime Aes192Aarch64 = AesAarch64[24]
"""AES-192 using the ARMv8 Crypto Extension implementation."""

comptime Aes256Aarch64 = AesAarch64[32]
"""AES-256 using the ARMv8 Crypto Extension implementation."""

comptime Aes128X86 = AesX86[16]
"""AES-128 using the x86 AES-NI implementation."""

comptime Aes192X86 = AesX86[24]
"""AES-192 using the x86 AES-NI implementation."""

comptime Aes256X86 = AesX86[32]
"""AES-256 using the x86 AES-NI implementation."""

comptime Aes128Gpu = AesGpu[16]
"""AES-128 using the GPU implementation."""

comptime Aes192Gpu = AesGpu[24]
"""AES-192 using the GPU implementation."""

comptime Aes256Gpu = AesGpu[32]
"""AES-256 using the GPU implementation."""
