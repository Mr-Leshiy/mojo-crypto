from std.bit import byte_swap
from std.sys.info import _current_target, is_little_endian, is_big_endian
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


def has_target_feature[
    name: __mlir_type.`!kgen.string`, //, feature: StringLiteral[name]
]() -> Bool:
    """Whether an LLVM target feature is enabled for this compilation.

    Feature names are LLVM's own, written *without* the leading `+` that
    `--target-features` uses — `"sha2"`, not `"+sha2"`.

    This answers a different question than `target_triple()`: the triple says
    which architecture is being compiled for, this says which of that
    architecture's optional extensions the compilation may actually emit. A
    hardware backend needs both, and gating on the triple alone is not enough
    — an intrinsic whose feature is off does not degrade gracefully, it fails
    the build outright (`LLVM ERROR: Cannot select: intrinsic
    %llvm.x86.vsha512rnds2`). Guarding with `comptime if` folds the branch
    away before the intrinsic is ever instantiated:

    ```mojo
    comptime if target_triple_contains_any(["x86_64"]) and has_target_feature[
        "sha512"
    ]():
        _compress_x86(state, block)
    else:
        _compress_naive(state, block)
    ```

    A feature LLVM does not recognise, or one belonging to a different
    architecture (asking for `"sha512"` on AArch64), is reported as disabled
    rather than raising — so a query is always safe to write, but a typo is
    silently False. Only a leading `+`/`-` is caught, as that is the one
    mistake the `--target-features` spelling invites.

    Parameters:
        name: The feature name as a raw MLIR string, inferred from `feature`.
        feature: The LLVM feature name to test, e.g. `"sha2"`.

    Returns:
        True if `feature` is enabled for the current compilation target.
    """
    comptime assert not (
        feature.startswith("+") or feature.startswith("-")
    ), "target feature name must be spelled without a leading '+' or '-'"

    return Bool(
        __mlir_attr[
            `#kgen.param.expr<target_has_feature,`,
            _current_target(),
            `,`,
            name,
            `> : i1`,
        ]
    )
