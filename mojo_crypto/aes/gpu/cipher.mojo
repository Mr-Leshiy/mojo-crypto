from std.gpu import thread_idx, block_idx, barrier
from std.gpu.memory import AddressSpace
from std.memory import UnsafePointer, stack_allocation

from ..common import Nb, BLOCK_SIZE


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
    mul2: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul3: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
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
        mix_columns(local_i, state, mul2, mul3)
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
    mul9: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul11: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul13: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul14: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
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
        inv_mix_columns(local_i, state, mul9, mul11, mul13, mul14)
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
    mul2: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul3: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
):
    var r = i % Nb
    var c = i // Nb
    var s0 = state[4 * c]
    var s1 = state[1 + 4 * c]
    var s2 = state[2 + 4 * c]
    var s3 = state[3 + 4 * c]
    barrier()
    if r == 0:
        state[i] = mul2[Int(s0)] ^ mul3[Int(s1)] ^ s2 ^ s3
    elif r == 1:
        state[i] = s0 ^ mul2[Int(s1)] ^ mul3[Int(s2)] ^ s3
    elif r == 2:
        state[i] = s0 ^ s1 ^ mul2[Int(s2)] ^ mul3[Int(s3)]
    else:
        state[i] = mul3[Int(s0)] ^ s1 ^ s2 ^ mul2[Int(s3)]
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
    mul9: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul11: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul13: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
    mul14: UnsafePointer[Scalar[DType.uint8], ImmutAnyOrigin],
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
            mul14[Int(s0)] ^ mul11[Int(s1)] ^ mul13[Int(s2)] ^ mul9[Int(s3)]
        )
    elif r == 1:
        state[i] = (
            mul9[Int(s0)] ^ mul14[Int(s1)] ^ mul11[Int(s2)] ^ mul13[Int(s3)]
        )
    elif r == 2:
        state[i] = (
            mul13[Int(s0)] ^ mul9[Int(s1)] ^ mul14[Int(s2)] ^ mul11[Int(s3)]
        )
    else:
        state[i] = (
            mul11[Int(s0)] ^ mul13[Int(s1)] ^ mul9[Int(s2)] ^ mul14[Int(s3)]
        )
    barrier()
