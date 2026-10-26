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
comptime HAS_AES = has_target_feature["aes"]()
# The SHA-2 instructions: SHA-224/256 need `sha` on x86 and `sha2` on aarch64;
# SHA-384/512 (and SHA-512/224, SHA-512/256) need `sha512` on x86 and `sha3`
# on aarch64.
comptime HAS_SHA256 = (IS_X86_64 and has_target_feature["sha"]()) or (
    IS_AARCH64 and has_target_feature["sha2"]()
)
comptime HAS_SHA512 = (IS_X86_64 and has_target_feature["sha512"]()) or (
    IS_AARCH64 and has_target_feature["sha3"]()
)


def register_platform_tests[test_funcs: Tuple, /](mut suite: TestSuite):
    """Registers every `test_*` function in `test_funcs` (usually
    `__functions_in_module()`) with `suite`, except the backend-specific ones
    the current build cannot run.

    A test is backend-specific when its name ends in `_aarch64`, `_x86` or
    `_gpu`, and is registered only when `IS_AARCH64`, `IS_X86_64` or `HAS_GPU`
    respectively is set. A test whose name contains `aes` also needs `HAS_AES`.
    An `_aarch64` or `_x86` test whose name contains `sha224` or `sha256` also
    needs `HAS_SHA256`, and one containing `sha384` or `sha512` needs
    `HAS_SHA512`. Every listed function is still compiled, so each backend's
    code must compile on any build.
    """
    comptime for i in range(len(test_funcs)):
        comptime name = get_function_name[test_funcs[i]]()
        comptime is_hw = name.endswith("_aarch64") or name.endswith("_x86")
        comptime if name.startswith("test_") and (
            (IS_AARCH64 or not name.endswith("_aarch64"))
            and (IS_X86_64 or not name.endswith("_x86"))
            and (HAS_GPU or not name.endswith("_gpu"))
            and (HAS_AES or not "aes" in name)
            and (
                HAS_SHA256
                or not (is_hw and ("sha224" in name or "sha256" in name))
            )
            and (
                HAS_SHA512
                or not (is_hw and ("sha384" in name or "sha512" in name))
            )
        ):
            suite.test[rebind[def() raises thin -> None](test_funcs[i])]()
