from std.gpu.host import DeviceContext, DeviceBuffer
from std.gpu.memory import AddressSpace
from std.gpu import thread_idx, block_idx, barrier
from std.memory import UnsafePointer, stack_allocation

from mojo_crypto.block_ciphers.errors import BlockSizeError
from .common import Nb, BLOCK_SIZE, SBOX, SBOX_INV
from .cpu import _key_expansion


struct AesGpuBackend[KeySize: Int](ImplicitlyDestructible, Movable):
    comptime Nk: Int = Self.KeySize // 4
    comptime Nr: Int = Self.Nk + 6
    comptime WordsSize: Int = Nb * (Self.Nr + 1)

    var ctx: DeviceContext
    var w: DeviceBuffer[DType.uint32]
    var sbox: DeviceBuffer[DType.uint32]
    var sbox_inv: DeviceBuffer[DType.uint8]

    def __init__(
        out self, ctx: DeviceContext, key: InlineArray[UInt8, Self.KeySize]
    ) raises:
        self.ctx = ctx
        var w = _key_expansion[WordsSize=Self.WordsSize, Nk=Self.Nk](key)
        self.w = ctx.enqueue_create_buffer[DType.uint32](Self.WordsSize)
        self.w.enqueue_copy_from(w)

        self.sbox = ctx.enqueue_create_buffer[DType.uint32](256)
        self.sbox.enqueue_copy_from(SBOX.unsafe_ptr())

        self.sbox_inv = ctx.enqueue_create_buffer[DType.uint8](256)
        self.sbox_inv.enqueue_copy_from(SBOX_INV.unsafe_ptr())

    def encrypt[Nr: Int, o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))

        var size = len(data)
        var num_blocks = size // BLOCK_SIZE
        comptime kernel = cipher[Nr]

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

    def decrypt[Nr: Int, o: MutOrigin](self, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))
        var size = len(data)
        var num_blocks = size // BLOCK_SIZE
        comptime kernel = decipher[Nr]

        var buf = self.ctx.enqueue_create_buffer[DType.uint8](size)
        buf.enqueue_copy_from(data.unsafe_ptr())

        self.ctx.enqueue_function[kernel, kernel](
            buf,
            self.w,
            self.sbox_inv,
            grid_dim=num_blocks,
            block_dim=BLOCK_SIZE,
        )

        buf.enqueue_copy_to(data.unsafe_ptr())


# FIPS 197 §5.1 Cipher()
# FIPS 197 §3.4: state[r][c] = in[r + 4*c] (column-major).
# All helpers operate directly on the flat InlineArray[UInt8, 16] using
# that index mapping: state[r][c] ↔ state[r + 4*c].
def cipher[
    Nr: Int
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

    add_round_key(local_i, state, 0, w)
    for r in range(1, Nr):
        sub_bytes(local_i, state, sbox)
        shift_rows(local_i, state)
        mix_columns(local_i, state)
        add_round_key(local_i, state, r, w)
    sub_bytes(local_i, state, sbox)
    shift_rows(local_i, state)
    add_round_key(local_i, state, Nr, w)

    in_out[global_i] = state[local_i]


# FIPS 197 §5.3 InvCipher()
def decipher[
    Nr: Int
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

    add_round_key(local_i, state, Nr, w)
    for r in range(Nr - 1, 0, -1):
        inv_shift_rows(local_i, state)
        inv_sub_bytes(local_i, state, sbox_inv)
        add_round_key(local_i, state, r, w)
        inv_mix_columns(local_i, state)
    inv_shift_rows(local_i, state)
    inv_sub_bytes(local_i, state, sbox_inv)
    add_round_key(local_i, state, 0, w)

    in_out[global_i] = state[local_i]


# FIPS 197 §5.1.4 AddRoundKey()
@always_inline
def add_round_key(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
    round: Int,
    w: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    var w_idx = Nb * round + i // Nb
    var offset = UInt32(24 - (i % Nb) * 8)
    state[i] ^= UInt8(w[w_idx] >> offset)


# FIPS 197 §5.1.1 SubBytes() — apply S-box to every byte of the state
@always_inline
def sub_bytes(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
    sbox: UnsafePointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    state[i] = UInt8(sbox[Int(state[i])])


# FIPS 197 §5.3.2 InvSubBytes() — apply inverse S-box to every byte
@always_inline
def inv_sub_bytes(
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
def shift_rows(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % Nb
    var c = i // Nb
    var tmp = state[r + 4 * ((c + r) % Nb)]
    barrier()
    state[i] = tmp
    barrier()


# FIPS 197 §5.3.1 InvShiftRows() — cyclic right shift of row r by r positions
@always_inline
def inv_shift_rows(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % Nb
    var c = i // Nb
    var tmp = state[r + 4 * ((c - r + Nb) % Nb)]
    barrier()
    state[i] = tmp
    barrier()


# FIPS 197 §5.1.3 MixColumns() — GF(2^8) matrix multiply on each column
# Thread i at (r=i%4, c=i//4) reads all 4 bytes of its column into registers,
# barriers to prevent write-before-read races, then writes only state[i]
@always_inline
def mix_columns(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % Nb
    var c = i // Nb
    var s0 = state[4 * c]
    var s1 = state[1 + 4 * c]
    var s2 = state[2 + 4 * c]
    var s3 = state[3 + 4 * c]
    barrier()
    if r == 0:
        state[i] = multiply(0x02, s0) ^ multiply(0x03, s1) ^ s2 ^ s3
    elif r == 1:
        state[i] = s0 ^ multiply(0x02, s1) ^ multiply(0x03, s2) ^ s3
    elif r == 2:
        state[i] = s0 ^ s1 ^ multiply(0x02, s2) ^ multiply(0x03, s3)
    else:
        state[i] = multiply(0x03, s0) ^ s1 ^ s2 ^ multiply(0x02, s3)
    barrier()


# FIPS 197 §5.3.3 InvMixColumns() — GF(2^8) inverse matrix multiply on each column
# Thread i at (r=i%4, c=i//4) reads all 4 bytes of its column into registers,
# barriers to prevent write-before-read races, then writes only state[i]
@always_inline
def inv_mix_columns(
    i: Int,
    state: UnsafePointer[
        Scalar[DType.uint8], MutAnyOrigin, address_space=AddressSpace.SHARED
    ],
):
    var r = i % Nb
    var c = i // Nb
    var s0 = state[4 * c]
    var s1 = state[1 + 4 * c]
    var s2 = state[2 + 4 * c]
    var s3 = state[3 + 4 * c]
    barrier()
    if r == 0:
        state[i] = (
            multiply(0x0E, s0)
            ^ multiply(0x0B, s1)
            ^ multiply(0x0D, s2)
            ^ multiply(0x09, s3)
        )
    elif r == 1:
        state[i] = (
            multiply(0x09, s0)
            ^ multiply(0x0E, s1)
            ^ multiply(0x0B, s2)
            ^ multiply(0x0D, s3)
        )
    elif r == 2:
        state[i] = (
            multiply(0x0D, s0)
            ^ multiply(0x09, s1)
            ^ multiply(0x0E, s2)
            ^ multiply(0x0B, s3)
        )
    else:
        state[i] = (
            multiply(0x0B, s0)
            ^ multiply(0x0D, s1)
            ^ multiply(0x09, s2)
            ^ multiply(0x0E, s3)
        )
    barrier()


# General GF(2^8) multiply via Russian peasant: iterate over bits of `a`
@always_inline
def multiply(a: UInt8, b: UInt8) -> UInt8:
    var result: UInt8 = 0
    var factor = b
    var scalar = a
    while scalar != 0:
        if scalar & 1:
            result ^= factor
        factor = xtime(factor)
        scalar >>= 1
    return result


# Multiply by 0x02 in GF(2^8) with AES reduction polynomial x^8+x^4+x^3+x+1
@always_inline
def xtime(a: UInt8) -> UInt8:
    var result = a << 1
    if a & 0x80:
        result ^= 0x1B
    return result
