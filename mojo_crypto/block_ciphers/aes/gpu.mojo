from std.gpu.host import DeviceContext, DeviceBuffer
from std.gpu.memory import AddressSpace
from std.gpu import thread_idx, block_idx, barrier
from std.memory import UnsafePointer, stack_allocation

from mojo_crypto.block_ciphers.traits import (
    BlockCipherDecryptable,
    BlockCipherEncryptable,
)
from mojo_crypto.block_ciphers.errors import BlockSizeError
from ._common import NB, BLOCK_SIZE, SBOX, SBOX_INV, _check_key_size
from .cpu import _key_expansion


struct AesGpu[KEY_SIZE: Int](
    BlockCipherDecryptable,
    BlockCipherEncryptable,
    Copyable,
    ImplicitlyDestructible,
    Movable,
):
    comptime BLOCK_SIZE: Int = BLOCK_SIZE

    comptime NK: Int = Self.KEY_SIZE // 4
    comptime NR: Int = Self.NK + 6
    comptime WORDS_SIZE: Int = NB * (Self.NR + 1)

    var ctx: DeviceContext
    var w: DeviceBuffer[DType.uint32]
    var sbox: DeviceBuffer[DType.uint32]
    var sbox_inv: DeviceBuffer[DType.uint8]

    def __init__(
        out self, ctx: DeviceContext, key: InlineArray[UInt8, Self.KEY_SIZE]
    ) raises:
        _check_key_size[Self.KEY_SIZE]()

        self.ctx = ctx
        var w = _key_expansion[WORDS_SIZE=Self.WORDS_SIZE, NK=Self.NK](key)
        self.w = ctx.enqueue_create_buffer[DType.uint32](Self.WORDS_SIZE)
        self.w.enqueue_copy_from(w)

        self.sbox = ctx.enqueue_create_buffer[DType.uint32](256)
        self.sbox.enqueue_copy_from(SBOX.unsafe_ptr())

        self.sbox_inv = ctx.enqueue_create_buffer[DType.uint8](256)
        self.sbox_inv.enqueue_copy_from(SBOX_INV.unsafe_ptr())

    def encrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))

        var size = len(data)
        var num_blocks = size // BLOCK_SIZE
        comptime kernel = _cipher[Self.NR]

        var buf = self.ctx.enqueue_create_buffer[DType.uint8](size)
        buf.enqueue_copy_from(data.unsafe_ptr())

        self.ctx.enqueue_function[kernel, kernel](
            buf,
            self.w,
            self.sbox,
            grid_dim=num_blocks,
            block_dim=BLOCK_SIZE,
        )
        self.ctx.synchronize()
        buf.enqueue_copy_to(data.unsafe_ptr())

    def decrypt[o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        var size = len(data)
        var num_blocks = size // BLOCK_SIZE
        comptime kernel = _decipher[Self.NR]

        var buf = self.ctx.enqueue_create_buffer[DType.uint8](size)
        buf.enqueue_copy_from(data.unsafe_ptr())

        self.ctx.enqueue_function[kernel, kernel](
            buf,
            self.w,
            self.sbox_inv,
            grid_dim=num_blocks,
            block_dim=BLOCK_SIZE,
        )
        self.ctx.synchronize()
        buf.enqueue_copy_to(data.unsafe_ptr())


# FIPS 197 §5.1 Cipher()
# FIPS 197 §3.4: state[r][c] = in[r + 4*c] (column-major).
# All helpers operate directly on the flat InlineArray[UInt8, 16] using
# that index mapping: state[r][c] ↔ state[r + 4*c].
def _cipher[
    NR: Int
](
    in_out: UnsafePointer[Scalar[DType.uint8], MutAnyOrigin],
    w: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
    sbox: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    var state = stack_allocation[
        BLOCK_SIZE, Scalar[DType.uint8], address_space=AddressSpace.SHARED
    ]()

    var local_i = thread_idx.x
    var global_i = block_idx.x * BLOCK_SIZE + local_i

    state[local_i] = in_out[global_i]

    _add_round_key(local_i, state, 0, w)
    for r in range(1, NR):
        _sub_bytes(local_i, state, sbox)
        _shift_rows(local_i, state)
        _mix_columns(local_i, state)
        _add_round_key(local_i, state, r, w)
    _sub_bytes(local_i, state, sbox)
    _shift_rows(local_i, state)
    _add_round_key(local_i, state, NR, w)

    in_out[global_i] = state[local_i]


# FIPS 197 §5.3 InvCipher()
def _decipher[
    NR: Int
](
    in_out: UnsafePointer[Scalar[DType.uint8], MutAnyOrigin],
    w: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
    sbox_inv: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    var state = stack_allocation[
        BLOCK_SIZE, Scalar[DType.uint8], address_space=AddressSpace.SHARED
    ]()

    var local_i = thread_idx.x
    var global_i = block_idx.x * BLOCK_SIZE + local_i

    state[local_i] = in_out[global_i]

    _add_round_key(local_i, state, NR, w)
    for r in range(NR - 1, 0, -1):
        _inv_shift_rows(local_i, state)
        _inv_sub_bytes(local_i, state, sbox_inv)
        _add_round_key(local_i, state, r, w)
        _inv_mix_columns(local_i, state)
    _inv_shift_rows(local_i, state)
    _inv_sub_bytes(local_i, state, sbox_inv)
    _add_round_key(local_i, state, 0, w)

    in_out[global_i] = state[local_i]


# FIPS 197 §5.1.4 AddRoundKey()
@always_inline
def _add_round_key(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
    round: Int,
    w: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    var w_idx = NB * round + i // NB
    var offset = UInt32(24 - (i % NB) * 8)
    state[i] ^= UInt8(w[w_idx] >> offset)


# FIPS 197 §5.1.1 SubBytes() — apply S-box to every byte of the state
@always_inline
def _sub_bytes(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
    sbox: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    state[i] = UInt8(sbox[Int(state[i])])


# FIPS 197 §5.3.2 InvSubBytes() — apply inverse S-box to every byte
@always_inline
def _inv_sub_bytes(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
    sbox_inv: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    state[i] = sbox_inv[Int(state[i])]


# FIPS 197 §5.1.2 ShiftRows() — cyclic left shift of row r by r positions
# Row r in flat layout occupies indices r, r+4, r+8, r+12
# Thread i handles byte at (r=i%4, c=i//4); reads from (r, (c+r)%4) of original
@always_inline
def _shift_rows(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % NB
    var c = i // NB
    var tmp = state[r + 4 * ((c + r) % NB)]
    barrier()
    state[i] = tmp
    barrier()


# FIPS 197 §5.3.1 InvShiftRows() — cyclic right shift of row r by r positions
@always_inline
def _inv_shift_rows(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % NB
    var c = i // NB
    var tmp = state[r + 4 * ((c - r + NB) % NB)]
    barrier()
    state[i] = tmp
    barrier()


# FIPS 197 §5.1.3 MixColumns() — GF(2^8) matrix multiply on each column
# Thread i at (r=i%4, c=i//4) reads all 4 bytes of its column into registers,
# barriers to prevent write-before-read races, then writes only state[i]
@always_inline
def _mix_columns(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % NB
    var c = i // NB
    var s0 = state[4 * c]
    var s1 = state[1 + 4 * c]
    var s2 = state[2 + 4 * c]
    var s3 = state[3 + 4 * c]
    barrier()
    if r == 0:
        state[i] = _multiply(0x02, s0) ^ _multiply(0x03, s1) ^ s2 ^ s3
    elif r == 1:
        state[i] = s0 ^ _multiply(0x02, s1) ^ _multiply(0x03, s2) ^ s3
    elif r == 2:
        state[i] = s0 ^ s1 ^ _multiply(0x02, s2) ^ _multiply(0x03, s3)
    else:
        state[i] = _multiply(0x03, s0) ^ s1 ^ s2 ^ _multiply(0x02, s3)
    barrier()


# FIPS 197 §5.3.3 InvMixColumns() — GF(2^8) inverse matrix multiply on each column
# Thread i at (r=i%4, c=i//4) reads all 4 bytes of its column into registers,
# barriers to prevent write-before-read races, then writes only state[i]
@always_inline
def _inv_mix_columns(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % NB
    var c = i // NB
    var s0 = state[4 * c]
    var s1 = state[1 + 4 * c]
    var s2 = state[2 + 4 * c]
    var s3 = state[3 + 4 * c]
    barrier()
    if r == 0:
        state[i] = (
            _multiply(0x0E, s0)
            ^ _multiply(0x0B, s1)
            ^ _multiply(0x0D, s2)
            ^ _multiply(0x09, s3)
        )
    elif r == 1:
        state[i] = (
            _multiply(0x09, s0)
            ^ _multiply(0x0E, s1)
            ^ _multiply(0x0B, s2)
            ^ _multiply(0x0D, s3)
        )
    elif r == 2:
        state[i] = (
            _multiply(0x0D, s0)
            ^ _multiply(0x09, s1)
            ^ _multiply(0x0E, s2)
            ^ _multiply(0x0B, s3)
        )
    else:
        state[i] = (
            _multiply(0x0B, s0)
            ^ _multiply(0x0D, s1)
            ^ _multiply(0x09, s2)
            ^ _multiply(0x0E, s3)
        )
    barrier()


# General GF(2^8) multiply via Russian peasant: iterate over bits of `a`
@always_inline
def _multiply(a: UInt8, b: UInt8) -> UInt8:
    var result: UInt8 = 0
    var factor = b
    var scalar = a
    while scalar != 0:
        if scalar & 1:
            result ^= factor
        factor = _xtime(factor)
        scalar >>= 1
    return result


# Multiply by 0x02 in GF(2^8) with AES reduction polynomial x^8+x^4+x^3+x+1
@always_inline
def _xtime(a: UInt8) -> UInt8:
    var result = a << 1
    if a & 0x80:
        result ^= 0x1B
    return result
