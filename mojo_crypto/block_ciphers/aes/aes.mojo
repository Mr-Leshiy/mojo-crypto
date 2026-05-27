from mojo_crypto.block_ciphers.traits import BlockCipher
from mojo_crypto.block_ciphers.errors import BlockSizeError


from .cpu.cipher import cipher as cpu_cipher, decipher as cpu_decipher
from .cpu.setup import AesCpuBackend
from .aarch64.cipher import cipher as armv8_cipher, decipher as armv8_decipher
from .aarch64.setup import AesArmv8Backend
from .x86.cipher import cipher as x86_cipher, decipher as x86_decipher
from .x86.setup import AesX86Backend
from .gpu.cipher import cipher as gpu_cipher, decipher as gpu_decipher
from .gpu.setup import AesGpuBackend
from .common import BLOCK_SIZE


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
            _encrypt_armv8(
                data, rebind[AesArmv8Backend[Self.KeySize]](self._backend)
            )
        elif reflect[Self.Backend]().name() == reflect[
            AesX86Backend[Self.KeySize]
        ]().name():
            _encrypt_x86(
                data, rebind[AesX86Backend[Self.KeySize]](self._backend)
            )
        elif reflect[Self.Backend]().name() == reflect[AesGpuBackend]().name():
            _encrypt_gpu[Self.Nr](rebind[AesGpuBackend](self._backend), data)
        else:
            _encrypt_cpu[Self.Nr](
                data, rebind[AesCpuBackend[Self.KeySize]](self._backend).w
            )

    def decrypt[o: MutOrigin](mut self, data: Span[UInt8, o]) raises:
        comptime if reflect[Self.Backend]().name() == reflect[
            AesArmv8Backend[Self.KeySize]
        ]().name():
            _decrypt_armv8(
                data, rebind[AesArmv8Backend[Self.KeySize]](self._backend)
            )
        elif reflect[Self.Backend]().name() == reflect[
            AesX86Backend[Self.KeySize]
        ]().name():
            _decrypt_x86(
                data, rebind[AesX86Backend[Self.KeySize]](self._backend)
            )
        elif reflect[Self.Backend]().name() == reflect[AesGpuBackend]().name():
            _decrypt_gpu[Self.Nr](rebind[AesGpuBackend](self._backend), data)
        else:
            _decrypt_cpu[Self.Nr](
                data, rebind[AesCpuBackend[Self.KeySize]](self._backend).w
            )


def _encrypt_armv8[
    KeySize: Int, o: MutOrigin
](data: Span[UInt8, o], armv8: AesArmv8Backend[KeySize]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        armv8_cipher(data[offset : offset + BLOCK_SIZE], armv8.enc_rks)


def _decrypt_armv8[
    KeySize: Int, o: MutOrigin
](data: Span[UInt8, o], armv8: AesArmv8Backend[KeySize]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        armv8_decipher(data[offset : offset + BLOCK_SIZE], armv8.dec_rks)


def _encrypt_x86[
    KeySize: Int, o: MutOrigin
](data: Span[UInt8, o], x86: AesX86Backend[KeySize]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        x86_cipher(data[offset : offset + BLOCK_SIZE], x86.enc_rks)


def _decrypt_x86[
    KeySize: Int, o: MutOrigin
](data: Span[UInt8, o], x86: AesX86Backend[KeySize]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        x86_decipher(data[offset : offset + BLOCK_SIZE], x86.dec_rks)


def _encrypt_cpu[
    Nr: Int, WordsSize: Int, o: MutOrigin
](data: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        cpu_cipher[Nr=Nr](data[offset : offset + BLOCK_SIZE], w)


def _decrypt_cpu[
    Nr: Int, WordsSize: Int, o: MutOrigin
](data: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        cpu_decipher[Nr=Nr](data[offset : offset + BLOCK_SIZE], w)


def _encrypt_gpu[
    Nr: Int, o: MutOrigin
](gpu: AesGpuBackend, data: Span[UInt8, o]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    var size = len(data)
    var num_blocks = size // BLOCK_SIZE
    comptime kernel = gpu_cipher[Nr]

    var buf = gpu.ctx.enqueue_create_buffer[DType.uint8](size)
    buf.enqueue_copy_from(data.unsafe_ptr())

    gpu.ctx.enqueue_function[kernel, kernel](
        buf,
        gpu.w,
        gpu.sbox,
        grid_dim=num_blocks,
        block_dim=BLOCK_SIZE,
    )

    buf.enqueue_copy_to(data.unsafe_ptr())


def _decrypt_gpu[
    Nr: Int, o: MutOrigin
](gpu: AesGpuBackend, data: Span[UInt8, o]) raises:
    BlockSizeError[BLOCK_SIZE].check(len(data))
    var size = len(data)
    var num_blocks = size // BLOCK_SIZE
    comptime kernel = gpu_decipher[Nr]

    var buf = gpu.ctx.enqueue_create_buffer[DType.uint8](size)
    buf.enqueue_copy_from(data.unsafe_ptr())

    gpu.ctx.enqueue_function[kernel, kernel](
        buf,
        gpu.w,
        gpu.sbox_inv,
        grid_dim=num_blocks,
        block_dim=BLOCK_SIZE,
    )

    buf.enqueue_copy_to(data.unsafe_ptr())
