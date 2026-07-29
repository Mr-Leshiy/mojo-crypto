from std.bit import byte_swap
from std.sys.info import _current_target, is_little_endian, is_big_endian
from std.memory import memcpy


@always_inline
def to_inline_array[
    size: Int,
    T: Copyable & Movable,
](data: List[T]) raises -> InlineArray[T, size]:
    """Copy a `size`-length List into a fixed-size InlineArray.

    Copies the underlying buffer in a single `memcpy` rather than
    element-by-element.

    Parameters:
        size: The expected length of `data` and of the resulting array.
        T: The element type.

    Args:
        data: The list to copy from.

    Returns:
        An `InlineArray[T, size]` holding a copy of `data`.

    Raises:
        Error: If `len(data) != size`.
    """
    if len(data) != size:
        raise Error(
            "expected list of length {}; got {}".format(size, len(data))
        )
    var arr = InlineArray[T, size](uninitialized=True)
    memcpy(dest=arr.unsafe_ptr(), src=data.unsafe_ptr(), count=size)
    return arr^


@always_inline
def to_list[
    size: Int, T: Copyable & Movable
](data: InlineArray[T, size]) -> List[T]:
    """Copy a fixed-size InlineArray into a List.

    Copies the underlying buffer in a single `memcpy` rather than
    element-by-element.

    Parameters:
        size: The length of `data` and of the resulting list.
        T: The element type.

    Args:
        data: The array to copy from.

    Returns:
        A `List[T]` holding a copy of `data`.
    """
    var list = List[T](unsafe_uninit_length=size)
    memcpy(dest=list.unsafe_ptr(), src=data.unsafe_ptr(), count=size)
    return list^


@always_inline
def load_be[dtype: DType, o: Origin](data: Span[UInt8, o]) -> Scalar[dtype]:
    """Assemble a big-endian word from a byte span.

    Every byte of `data` is consumed, most-significant first; the caller
    picks `dtype` and slices `data` to the matching byte width (e.g. 4 bytes
    for `DType.uint32`, 8 bytes for `DType.uint64`).

    Parameters:
        dtype: The scalar type to assemble.
        o: The origin of the byte span.

    Args:
        data: The big-endian bytes to assemble.

    Returns:
        The assembled `Scalar[dtype]` value.
    """
    var word: Scalar[dtype] = 0
    for i in range(len(data)):
        word = (word << 8) | Scalar[dtype](data[i])
    return word


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

    Useful for detecting an architecture family that has no dedicated
    `CompilationTarget` predicate.

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
