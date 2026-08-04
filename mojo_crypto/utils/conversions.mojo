"""Conversions between the container and word representations of key material.

`to_inline_array`/`to_list` move a fixed-size buffer between `InlineArray` and
`List` (test vectors arrive as lists, the primitives take arrays); `load_be`
assembles a big-endian word out of a byte span.
"""

from std.sys import size_of, is_big_endian


@always_inline
def to_bytes[
    dtype: DType,
    output_size: Int,
    input_size: Int,
    big_endian: Bool = is_big_endian(),
](input: SIMD[dtype, input_size]) -> InlineArray[UInt8, output_size]:
    """Reinterpret a SIMD vector as its `output_size` bytes.

    `SIMD.as_bytes` is typed `Array[UInt8, size_of[Self]()]`, a size expression
    that is not folded at parse time, so the result has to be rebound to the
    caller's `output_size`. The size equality is checked here rather than in a
    `where` clause: a `where` clause must be *proven* where the call is written,
    and `size_of` cannot be evaluated while the lane count is still symbolic —
    a generic caller such as `_reverse[SIZE]` would be rejected even though
    every concrete instantiation is sound.

    Parameters:
        dtype: The lane type of the input vector.
        output_size: The length of the returned byte array.
        input_size: The number of lanes in the input vector.
        big_endian: Whether to emit each lane big-endian; defaults to the
            target's own byte order, matching a raw memory reinterpretation.

    Args:
        input: The vector to reinterpret.

    Returns:
        The `output_size` bytes of `input`.
    """
    comptime assert (
        size_of[SIMD[dtype, input_size]]() == output_size
    ), "to_bytes: output_size must equal the byte width of the input vector"

    return rebind_var[InlineArray[UInt8, output_size]](
        input.as_bytes[big_endian=big_endian]()
    )


@always_inline
def to_inline_array[
    size: Int,
    T: Copyable & Deinitable,
](data: List[T]) raises -> InlineArray[T, size]:
    """Copy a `size`-length List into a fixed-size InlineArray.

    Copies the underlying buffer in a single `Span.copy_from` rather than
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
    Span(arr).copy_from(Span(data))
    return arr^


@always_inline
def to_list[
    size: Int, T: Copyable & Deinitable
](data: InlineArray[T, size]) -> List[T]:
    """Copy a fixed-size InlineArray into a List.

    Copies the underlying buffer in a single `Span.copy_from` rather than
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
    Span(list).copy_from(Span(data))
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
