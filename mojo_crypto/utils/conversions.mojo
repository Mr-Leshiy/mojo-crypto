"""Conversions between the container and word representations of key material.

`to_inline_array`/`to_list` move a fixed-size buffer between `InlineArray` and
`List` (test vectors arrive as lists, the primitives take arrays); `load_be`
assembles a big-endian word out of a byte span.
"""

from std.memory import unsafe_memcpy


@always_inline
def to_inline_array[
    size: Int,
    T: Movable,
](data: List[T]) raises -> InlineArray[T, size]:
    """Copy a `size`-length List into a fixed-size InlineArray.

    Copies the underlying buffer in a single `unsafe_memcpy` rather than
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
    unsafe_memcpy(dest=arr.unsafe_ptr(), src=data.unsafe_ptr(), count=size)
    return arr^


@always_inline
def to_list[size: Int, T: Movable](data: InlineArray[T, size]) -> List[T]:
    """Copy a fixed-size InlineArray into a List.

    Copies the underlying buffer in a single `unsafe_memcpy` rather than
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
    unsafe_memcpy(dest=list.unsafe_ptr(), src=data.unsafe_ptr(), count=size)
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
