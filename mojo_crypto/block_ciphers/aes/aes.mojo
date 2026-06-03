from mojo_crypto.block_ciphers.traits import BlockCipher

from .cpu import AesCpuBackend
from .aarch64 import AesArmv8Backend
from .x86 import AesX86Backend
from .gpu import AesGpuBackend


# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
#
# Backend selects the implementation at compile time:
#   AesArmv8Backend[KeySize]  — AArch64 AES crypto extension
#   AesX86Backend[KeySize]    — x86 AES-NI
#   AesCpuBackend[KeySize]    — portable software fallback
#   AesGpuBackend             — CUDA GPU backend
#
struct Aes[KeySize: Int, Backend: Movable & ImplicitlyDestructible](
    BlockCipher, ImplicitlyDestructible, Movable
):
    comptime Nr: Int = AesCpuBackend[Self.KeySize].Nr
    comptime BLOCK_SIZE: Int = 16

    var _backend: Self.Backend

    def __init__(out self, var backend: Self.Backend):
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"
        self._backend = backend^

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if reflect[Self.Backend]().name() == reflect[
            AesArmv8Backend[Self.KeySize]
        ]().name():
            rebind[AesArmv8Backend[Self.KeySize]](self._backend).encrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesX86Backend[Self.KeySize]
        ]().name():
            rebind[AesX86Backend[Self.KeySize]](self._backend).encrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesGpuBackend[Self.KeySize]
        ]().name():
            rebind[AesGpuBackend[Self.KeySize]](self._backend).encrypt(data)
        else:
            rebind[AesCpuBackend[Self.KeySize]](self._backend).encrypt(data)

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if reflect[Self.Backend]().name() == reflect[
            AesArmv8Backend[Self.KeySize]
        ]().name():
            rebind[AesArmv8Backend[Self.KeySize]](self._backend).decrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesX86Backend[Self.KeySize]
        ]().name():
            rebind[AesX86Backend[Self.KeySize]](self._backend).decrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesGpuBackend[Self.KeySize]
        ]().name():
            rebind[AesGpuBackend[Self.KeySize]](self._backend).decrypt(data)
        else:
            rebind[AesCpuBackend[Self.KeySize]](self._backend).decrypt(data)
