from std.gpu.host import DeviceContext
from std.memory import memcpy

from mojo_crypto.block_cipher import BlockCipher
from mojo_crypto.errors import BlockSizeError

from std.sys import CompilationTarget

from .cpu.cipher import cipher as cpu_cipher, decipher as cpu_decipher
from .cpu.setup import AesCpuSetup
from .armv8.cipher import cipher as armv8_cipher, decipher as armv8_decipher
from .armv8.setup import AesArmv8Setup
from .gpu.cipher import cipher as gpu_cipher, decipher as gpu_decipher
from .gpu.setup import AesGpuSetup
from .common import BLOCK_SIZE


# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
struct Aes[KeySize: Int](BlockCipher, ImplicitlyDestructible):
    comptime Nr: Int = AesCpuSetup[Self.KeySize].Nr

    var _cpu: AesCpuSetup[Self.KeySize]
    var _armv8: Optional[AesArmv8Setup[Self.KeySize]]
    var _gpu: Optional[AesGpuSetup]

    def __init__(
        out self,
        key: InlineArray[UInt8, Self.KeySize],
        ctx: Optional[DeviceContext] = None,
    ) raises:
        comptime assert (
            Self.KeySize == 16 or Self.KeySize == 24 or Self.KeySize == 32
        ), "KeySize must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)"
        self._cpu = AesCpuSetup[Self.KeySize](key)
        comptime if not CompilationTarget.is_x86():
            self._armv8 = AesArmv8Setup[Self.KeySize](key)
        else:
            self._armv8 = None
        if ctx:
            self._gpu = AesGpuSetup(ctx.value(), self._cpu.w)
        else:
            self._gpu = None

    def encrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        if self._gpu:
            _encrypt_gpu[Self.Nr](self._gpu.value(), data)
        else:
            comptime if not CompilationTarget.is_x86():
                _encrypt_armv8(data, self._armv8.value())
            else:
                _encrypt_cpu[Self.Nr](data, self._cpu.w)

    def decrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        if self._gpu:
            _decrypt_gpu[Self.Nr](self._gpu.value(), data)
        else:
            comptime if not CompilationTarget.is_x86():
                _decrypt_armv8(data, self._armv8.value())
            else:
                _decrypt_cpu[Self.Nr](data, self._cpu.w)


def _check_block_aligned(size: Int) raises:
    if size % BLOCK_SIZE != 0:
        raise BlockSizeError(size)


def _encrypt_armv8[
    KeySize: Int, o: MutOrigin
](data: Span[UInt8, o], armv8: AesArmv8Setup[KeySize]) raises:
    _check_block_aligned(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        armv8_cipher(data[offset : offset + BLOCK_SIZE], armv8.enc_rks)


def _decrypt_armv8[
    KeySize: Int, o: MutOrigin
](data: Span[UInt8, o], armv8: AesArmv8Setup[KeySize]) raises:
    _check_block_aligned(len(data))
    for i in range(len(data) // BLOCK_SIZE):
        var offset = i * BLOCK_SIZE
        armv8_decipher(data[offset : offset + BLOCK_SIZE], armv8.dec_rks)


def _encrypt_cpu[
    Nr: Int, WordsSize: Int, o: MutOrigin
](data: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]) raises:
    _check_block_aligned(len(data))
    var block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
    for i in range(len(data) // BLOCK_SIZE):
        memcpy(
            dest=block.unsafe_ptr(),
            src=data.unsafe_ptr() + i * BLOCK_SIZE,
            count=BLOCK_SIZE,
        )
        cpu_cipher[Nr=Nr](block, w)
        memcpy(
            dest=data.unsafe_ptr() + i * BLOCK_SIZE,
            src=block.unsafe_ptr(),
            count=BLOCK_SIZE,
        )


def _decrypt_cpu[
    Nr: Int, WordsSize: Int, o: MutOrigin
](data: Span[UInt8, o], w: InlineArray[UInt32, WordsSize]) raises:
    _check_block_aligned(len(data))
    var block = InlineArray[UInt8, BLOCK_SIZE](uninitialized=True)
    for i in range(len(data) // BLOCK_SIZE):
        memcpy(
            dest=block.unsafe_ptr(),
            src=data.unsafe_ptr() + i * BLOCK_SIZE,
            count=BLOCK_SIZE,
        )
        cpu_decipher[Nr=Nr](block, w)
        memcpy(
            dest=data.unsafe_ptr() + i * BLOCK_SIZE,
            src=block.unsafe_ptr(),
            count=BLOCK_SIZE,
        )


def _encrypt_gpu[Nr: Int, o: MutOrigin](
    gpu: AesGpuSetup, data: Span[UInt8, o]
) raises:
    _check_block_aligned(len(data))
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


def _decrypt_gpu[Nr: Int, o: MutOrigin](
    gpu: AesGpuSetup, data: Span[UInt8, o]
) raises:
    _check_block_aligned(len(data))
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
