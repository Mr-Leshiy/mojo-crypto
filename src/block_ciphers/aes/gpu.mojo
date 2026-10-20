from max.gpu.host import DeviceBuffer
from max.gpu.memory import AddressSpace
from max.gpu.sync import barrier
from max.gpu import thread_idx, block_idx
from std.builtin.globals import global_constant
from std.memory import stack_allocation, unsafe_memcpy
from warp import Context

from ..traits import (
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
)
from ..errors import BlockSizeError
from .common import NB, BLOCK_SIZE, SBOX, SBOX_INV, _check_key_size
from .naive import _key_expansion


struct AesGpu[KEY_SIZE: Int](
    AsyncBlockCipherDecryptable,
    AsyncBlockCipherEncryptable,
    Copyable,
    Deinitable,
    Movable,
):
    comptime BLOCK_SIZE: Int = BLOCK_SIZE

    comptime NK: Int = Self.KEY_SIZE // 4
    comptime NR: Int = Self.NK + 6
    comptime WORDS_SIZE: Int = NB * (Self.NR + 1)

    var w: DeviceBuffer[DType.uint32]
    var sbox: DeviceBuffer[DType.uint32]
    var sbox_inv: DeviceBuffer[DType.uint8]

    def __init__(
        out self,
        *,
        var w: DeviceBuffer[DType.uint32],
        var sbox: DeviceBuffer[DType.uint32],
        var sbox_inv: DeviceBuffer[DType.uint8],
    ):
        self.w = w^
        self.sbox = sbox^
        self.sbox_inv = sbox_inv^

    @staticmethod
    __async def create(
        ctx: Context, key: Array[UInt8, Self.KEY_SIZE]
    ) raises -> Self:
        """Upload the key schedule and S-boxes, and return the cipher once they
        have landed on the device."""
        _check_key_size[Self.KEY_SIZE]()

        var w = _key_expansion[WORDS_SIZE=Self.WORDS_SIZE, NK=Self.NK](key)

        # The S-box uploads read from the binary's read-only data, which lives
        # for the whole program. `w` is a local in this coroutine's frame, so
        # it too stays alive across the `await`.
        var cipher = Self(
            w=ctx.enqueue_device_buffer(w),
            sbox=ctx.enqueue_device_buffer(global_constant[SBOX]()),
            sbox_inv=ctx.enqueue_device_buffer(global_constant[SBOX_INV]()),
        )
        __await ctx.synchronize()
        return cipher^

    __async def encrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))

        var device = ctx.enqueue_device_buffer(data)
        _launch_cipher[Self.NR](ctx, device, self.w, self.sbox)
        var host = ctx.enqueue_host_buffer(device)
        __await ctx.synchronize()
        unsafe_memcpy(
            dest=data.unsafe_ptr(), src=host.unsafe_ptr(), count=len(data)
        )

    __async def decrypt[
        o: MutOrigin
    ](mut self, ctx: Context, data: Span[UInt8, o]) raises:
        BlockSizeError[BLOCK_SIZE].check(len(data))

        var device = ctx.enqueue_device_buffer(data)
        _launch_decipher[Self.NR](ctx, device, self.w, self.sbox_inv)
        var host = ctx.enqueue_host_buffer(device)
        __await ctx.synchronize()
        unsafe_memcpy(
            dest=data.unsafe_ptr(), src=host.unsafe_ptr(), count=len(data)
        )


# `enqueue_function` called directly inside an `async def` crashes the
# compiler (https://github.com/modular/modular/issues/7249), so the kernel
# launches live in plain `def`s.
def _launch_cipher[
    NR: Int
](
    ctx: Context,
    buf: DeviceBuffer[DType.uint8],
    w: DeviceBuffer[DType.uint32],
    sbox: DeviceBuffer[DType.uint32],
) raises:
    ctx.gpu_ctx().enqueue_function[_cipher[NR]](
        buf,
        w,
        sbox,
        grid_dim=len(buf) // BLOCK_SIZE,
        block_dim=BLOCK_SIZE,
    )


def _launch_decipher[
    NR: Int
](
    ctx: Context,
    buf: DeviceBuffer[DType.uint8],
    w: DeviceBuffer[DType.uint32],
    sbox_inv: DeviceBuffer[DType.uint8],
) raises:
    ctx.gpu_ctx().enqueue_function[_decipher[NR]](
        buf,
        w,
        sbox_inv,
        grid_dim=len(buf) // BLOCK_SIZE,
        block_dim=BLOCK_SIZE,
    )


# FIPS 197 §5.1 Cipher()
# FIPS 197 §3.4: state[r][c] = in[r + 4*c] (column-major).
# All helpers operate directly on the flat Array[UInt8, 16] using
# that index mapping: state[r][c] ↔ state[r + 4*c].
def _cipher[
    NR: Int
](
    in_out: Pointer[Scalar[DType.uint8], MutAnyOrigin],
    w: Pointer[Scalar[DType.uint32], ImmutAnyOrigin],
    sbox: Pointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    var state = stack_allocation[
        BLOCK_SIZE, Scalar[DType.uint8], address_space=AddressSpace.SHARED
    ]()

    var local_i = thread_idx.x
    var global_i = block_idx.x * BLOCK_SIZE + local_i

    state[unsafe_offset=local_i] = in_out[unsafe_offset=global_i]

    _add_round_key(local_i, state, 0, w)
    for r in range(1, NR):
        _sub_bytes(local_i, state, sbox)
        _shift_rows(local_i, state)
        _mix_columns(local_i, state)
        _add_round_key(local_i, state, r, w)
    _sub_bytes(local_i, state, sbox)
    _shift_rows(local_i, state)
    _add_round_key(local_i, state, NR, w)

    in_out[unsafe_offset=global_i] = state[unsafe_offset=local_i]


# FIPS 197 §5.3 InvCipher()
def _decipher[
    NR: Int
](
    in_out: Pointer[Scalar[DType.uint8], MutAnyOrigin],
    w: Pointer[Scalar[DType.uint32], ImmutAnyOrigin],
    sbox_inv: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    var state = stack_allocation[
        BLOCK_SIZE, Scalar[DType.uint8], address_space=AddressSpace.SHARED
    ]()

    var local_i = thread_idx.x
    var global_i = block_idx.x * BLOCK_SIZE + local_i

    state[unsafe_offset=local_i] = in_out[unsafe_offset=global_i]

    _add_round_key(local_i, state, NR, w)
    for r in range(NR - 1, 0, -1):
        _inv_shift_rows(local_i, state)
        _inv_sub_bytes(local_i, state, sbox_inv)
        _add_round_key(local_i, state, r, w)
        _inv_mix_columns(local_i, state)
    _inv_shift_rows(local_i, state)
    _inv_sub_bytes(local_i, state, sbox_inv)
    _add_round_key(local_i, state, 0, w)

    in_out[unsafe_offset=global_i] = state[unsafe_offset=local_i]


# FIPS 197 §5.1.4 AddRoundKey()
@always_inline
def _add_round_key(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
    round: Int,
    w: Pointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    var w_idx = NB * round + i // NB
    var offset = UInt32(24 - (i % NB) * 8)
    state[unsafe_offset=i] ^= UInt8(w[unsafe_offset=w_idx] >> offset)


# FIPS 197 §5.1.1 SubBytes() — apply S-box to every byte of the state
@always_inline
def _sub_bytes(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
    sbox: Pointer[Scalar[DType.uint32], ImmutAnyOrigin],
):
    state[unsafe_offset=i] = UInt8(
        sbox[unsafe_offset=Int(state[unsafe_offset=i])]
    )


# FIPS 197 §5.3.2 InvSubBytes() — apply inverse S-box to every byte
@always_inline
def _inv_sub_bytes(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
    sbox_inv: Pointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    state[unsafe_offset=i] = sbox_inv[unsafe_offset=Int(state[unsafe_offset=i])]


# FIPS 197 §5.1.2 ShiftRows() — cyclic left shift of row r by r positions
# Row r in flat layout occupies indices r, r+4, r+8, r+12
# Thread i handles byte at (r=i%4, c=i//4); reads from (r, (c+r)%4) of original
@always_inline
def _shift_rows(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
):
    var r = i % NB
    var c = i // NB
    var tmp = state[unsafe_offset=r + 4 * ((c + r) % NB)]
    barrier()
    state[unsafe_offset=i] = tmp
    barrier()


# FIPS 197 §5.3.1 InvShiftRows() — cyclic right shift of row r by r positions
@always_inline
def _inv_shift_rows(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
):
    var r = i % NB
    var c = i // NB
    var tmp = state[unsafe_offset=r + 4 * ((c - r + NB) % NB)]
    barrier()
    state[unsafe_offset=i] = tmp
    barrier()


# FIPS 197 §5.1.3 MixColumns() — GF(2^8) matrix multiply on each column
# Thread i at (r=i%4, c=i//4) reads all 4 bytes of its column into registers,
# barriers to prevent write-before-read races, then writes only state[i]
@always_inline
def _mix_columns(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
):
    var r = i % NB
    var c = i // NB
    var s0 = state[unsafe_offset=4 * c]
    var s1 = state[unsafe_offset=1 + 4 * c]
    var s2 = state[unsafe_offset=2 + 4 * c]
    var s3 = state[unsafe_offset=3 + 4 * c]
    barrier()
    if r == 0:
        state[unsafe_offset=i] = (
            _multiply(0x02, s0) ^ _multiply(0x03, s1) ^ s2 ^ s3
        )
    elif r == 1:
        state[unsafe_offset=i] = (
            s0 ^ _multiply(0x02, s1) ^ _multiply(0x03, s2) ^ s3
        )
    elif r == 2:
        state[unsafe_offset=i] = (
            s0 ^ s1 ^ _multiply(0x02, s2) ^ _multiply(0x03, s3)
        )
    else:
        state[unsafe_offset=i] = (
            _multiply(0x03, s0) ^ s1 ^ s2 ^ _multiply(0x02, s3)
        )
    barrier()


# FIPS 197 §5.3.3 InvMixColumns() — GF(2^8) inverse matrix multiply on each column
# Thread i at (r=i%4, c=i//4) reads all 4 bytes of its column into registers,
# barriers to prevent write-before-read races, then writes only state[i]
@always_inline
def _inv_mix_columns(
    i: Int,
    state: Pointer[
        Scalar[DType.uint8],
        MutUntrackedOrigin,
        address_space=AddressSpace.SHARED,
    ],
):
    var r = i % NB
    var c = i // NB
    var s0 = state[unsafe_offset=4 * c]
    var s1 = state[unsafe_offset=1 + 4 * c]
    var s2 = state[unsafe_offset=2 + 4 * c]
    var s3 = state[unsafe_offset=3 + 4 * c]
    barrier()
    if r == 0:
        state[unsafe_offset=i] = (
            _multiply(0x0E, s0)
            ^ _multiply(0x0B, s1)
            ^ _multiply(0x0D, s2)
            ^ _multiply(0x09, s3)
        )
    elif r == 1:
        state[unsafe_offset=i] = (
            _multiply(0x09, s0)
            ^ _multiply(0x0E, s1)
            ^ _multiply(0x0B, s2)
            ^ _multiply(0x0D, s3)
        )
    elif r == 2:
        state[unsafe_offset=i] = (
            _multiply(0x0D, s0)
            ^ _multiply(0x09, s1)
            ^ _multiply(0x0E, s2)
            ^ _multiply(0x0B, s3)
        )
    else:
        state[unsafe_offset=i] = (
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
