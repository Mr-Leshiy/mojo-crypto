from std.bit import byte_swap
from std.sys.info import _current_target, is_little_endian, is_big_endian
from std.memory import memcpy


def to_le_bytes[
    dtype: DType, width: Int
](value: SIMD[dtype, width]) -> SIMD[dtype, width]:
    """Return `value` laid out little-endian in memory.

    A no-op on little-endian targets; on a big-endian target each lane is
    byte-swapped so that storing the result yields little-endian bytes. The
    branch is resolved at compile time, so it costs nothing on little-endian
    targets.

    Parameters:
        dtype: The element type of the vector (inferred from the argument).
        width: The number of lanes (inferred from the argument).

    Args:
        value: The integer scalar or vector to reorder.

    Returns:
        `value` with each lane's bytes in little-endian order.
    """
    comptime if is_big_endian():
        return byte_swap(value)
    return value


def to_be_bytes[
    dtype: DType, width: Int
](value: SIMD[dtype, width]) -> SIMD[dtype, width]:
    """Return `value` laid out big-endian in memory.

    A no-op on big-endian targets; on a little-endian target each lane is
    byte-swapped so that storing the result yields big-endian bytes. The branch
    is resolved at compile time, so it costs nothing on big-endian targets.

    Parameters:
        dtype: The element type of the vector (inferred from the argument).
        width: The number of lanes (inferred from the argument).

    Args:
        value: The integer scalar or vector to reorder.

    Returns:
        `value` with each lane's bytes in big-endian order.
    """
    comptime if is_little_endian():
        return byte_swap(value)
    return value


def to_inline_array[
    size: Int
](data: List[UInt8]) raises -> InlineArray[UInt8, size]:
    """Copy a `size`-length List into a fixed-size InlineArray.

    Raises if `len(data) != size`.
    """
    if len(data) != size:
        raise Error(
            "expected list of length {}; got {}".format(size, len(data))
        )
    var arr = InlineArray[UInt8, size](uninitialized=True)
    memcpy(dest=arr.unsafe_ptr(), src=data.unsafe_ptr(), count=size)
    return arr^


def target_triple() -> StaticString:
    """The current compilation target triple, e.g. "x86_64-unknown-linux-gnu".

    Useful for selecting an architecture-specific backend. Prefer the dedicated
    `CompilationTarget` predicates (e.g. `has_neon()`) where they exist; note that
    `CompilationTarget.is_x86()` only matches 32-bit x86, not x86-64, so matching
    on this triple is the reliable way to detect an x86-64 target.

    Returns:
        The target triple of the current compilation target.
    """
    return StringLiteral[
        __mlir_attr[
            `#kgen.param.expr<target_get_field,`,
            _current_target(),
            `, "triple" : !kgen.string> : !kgen.string`,
        ]
    ]()


def target_triple_contains_any(needles: List[StaticString]) -> Bool:
    """Whether the current target triple contains any of the given substrings.

    Takes an `InlineArray` so the whole check can be folded at compile time,
    e.g. `comptime is_x86 = target_triple_with(["x86_64", "amd64"])`. Useful for
    detecting an architecture family that has no dedicated `CompilationTarget`
    predicate.

    Parameters:
        size: The number of substrings (inferred from the argument).

    Args:
        needles: Substrings to look for in the target triple.

    Returns:
        True if the target triple contains at least one of `needles`.
    """
    var triple = target_triple()
    for needle in needles:
        if needle in triple:
            return True
    return False
