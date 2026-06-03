from mojo_crypto.block_ciphers.traits import BlockCipher

from .cpu import AesCpu
from .aarch64 import AesAarch64
from .x86 import AesX86
from .gpu import AesGpu


# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
#
# Backend selects the implementation at compile time:
#   AesAarch64[KeySize]  — AArch64 AES crypto extension
#   AesX86[KeySize]    — x86 AES-NI
#   AesCpu[KeySize]    — portable software fallback
#   AesGpu             — CUDA GPU backend
#
struct Aes[KeySize: Int, Backend: Movable & ImplicitlyDestructible](
    BlockCipher, ImplicitlyDestructible, Movable
):
    comptime Nr: Int = AesCpu[Self.KeySize].Nr
    comptime BLOCK_SIZE: Int = 16

    var _backend: Self.Backend

    def __init__(out self, var backend: Self.Backend):
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"
        self._backend = backend^

    def encrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if reflect[Self.Backend]().name() == reflect[
            AesAarch64[Self.KeySize]
        ]().name():
            rebind[AesAarch64[Self.KeySize]](self._backend).encrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesX86[Self.KeySize]
        ]().name():
            rebind[AesX86[Self.KeySize]](self._backend).encrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesGpu[Self.KeySize]
        ]().name():
            rebind[AesGpu[Self.KeySize]](self._backend).encrypt(data)
        else:
            rebind[AesCpu[Self.KeySize]](self._backend).encrypt(data)

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if reflect[Self.Backend]().name() == reflect[
            AesAarch64[Self.KeySize]
        ]().name():
            rebind[AesAarch64[Self.KeySize]](self._backend).decrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesX86[Self.KeySize]
        ]().name():
            rebind[AesX86[Self.KeySize]](self._backend).decrypt(data)
        elif reflect[Self.Backend]().name() == reflect[
            AesGpu[Self.KeySize]
        ]().name():
            rebind[AesGpu[Self.KeySize]](self._backend).decrypt(data)
        else:
            rebind[AesCpu[Self.KeySize]](self._backend).decrypt(data)
