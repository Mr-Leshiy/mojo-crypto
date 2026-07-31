# SHA-2 (32-bit word) via the ARMv8 SHA-256 Crypto Extension.
#
# LLVM AArch64 intrinsic definitions (no separate doc page exists; .td is authoritative):
#   https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/IntrinsicsAArch64.td

from .common import SHA2_WORD32_BLOCK_SIZE


# FIPS 180-4 §6.2.2 — the SHA-256 compression function,
# via the ARMv8 SHA-256 Crypto Extension.
def _compress(
    mut state: SIMD[DType.uint32, 8],
    block: InlineArray[UInt8, SHA2_WORD32_BLOCK_SIZE],
):
    var abcd = state.slice[4]()
    var efgh = state.slice[4, offset=4]()
