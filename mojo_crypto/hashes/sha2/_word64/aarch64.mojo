# SHA-2 (64-bit word) via the ARMv8.2 SHA-512 Crypto Extension.
#
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td

from .common import SHA2_WORD64_BLOCK_SIZE


# FIPS 180-4 §6.4.2 — the SHA-512 compression function,
# via the ARMv8.2 SHA-512 Crypto Extension.
def _compress(
    mut state: SIMD[DType.uint64, 8],
    block: InlineArray[UInt8, SHA2_WORD64_BLOCK_SIZE],
):
    # TODO: implement with sha512su0/sha512su1 for the message schedule and
    # sha512h/sha512h2 for the 80 rounds.
    _ = block
    pass
