"""Compile-time flags describing what the current test build can run.

A test suite registers the tests of a backend only when its flag is set: the
hardware backends are compiled in only for their target and CPU features, and
without an accelerator the GPU kernels cannot even be compiled.
"""

from std.sys import has_accelerator

from mojo_crypto.utils import target_triple_contains_any, has_target_feature

comptime IS_AARCH64 = target_triple_contains_any(["aarch64", "arm64"])
comptime IS_X86_64 = target_triple_contains_any(["x86_64"])
comptime HAS_GPU = has_accelerator()

comptime HAS_AES_AARCH64 = IS_AARCH64 and has_target_feature["aes"]()
comptime HAS_AES_X86 = IS_X86_64 and has_target_feature["aes"]()
