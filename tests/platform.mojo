"""Compile-time flags describing what the current test build can run, and a
helper that registers only the tests the build can run.

A test suite registers the tests of a backend only when its flag is set: the
hardware backends are compiled in only for their target and CPU features, and
without an accelerator the GPU kernels cannot even be compiled.
"""

from std.reflection import get_function_name
from std.sys import has_accelerator
from std.testing import TestSuite

from mojo_crypto.utils import target_triple_contains_any, has_target_feature

comptime IS_AARCH64 = target_triple_contains_any(["aarch64", "arm64"])
comptime IS_X86_64 = target_triple_contains_any(["x86_64"])
comptime HAS_GPU = has_accelerator()

comptime HAS_AES_AARCH64 = IS_AARCH64 and has_target_feature["aes"]()
comptime HAS_AES_X86 = IS_X86_64 and has_target_feature["aes"]()


def register_platform_tests[test_funcs: Tuple, /](mut suite: TestSuite):
    """Registers every `test_*` function in `test_funcs` (usually
    `__functions_in_module()`) with `suite`, except the backend-specific ones
    the current build cannot run.

    A test is backend-specific when its name ends in `_aarch64`, `_x86` or
    `_gpu`, and is registered only when `HAS_AES_AARCH64`, `HAS_AES_X86` or
    `HAS_GPU` respectively is set. Every listed function is still compiled, so
    each backend's code must compile on any build.
    """
    comptime for i in range(len(test_funcs)):
        comptime name = get_function_name[test_funcs[i]]()
        comptime if name.startswith("test_") and (
            (HAS_AES_AARCH64 or not name.endswith("_aarch64"))
            and (HAS_AES_X86 or not name.endswith("_x86"))
            and (HAS_GPU or not name.endswith("_gpu"))
        ):
            suite.test[rebind[def() raises thin -> None](test_funcs[i])]()
