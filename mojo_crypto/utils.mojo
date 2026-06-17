from std.sys.info import _current_target


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
