#!/usr/bin/env bash
# Runs the Mojo test suite. Wrapped in a real shell (rather than inlined in
# pixi.toml) because pixi's cross-platform task shell doesn't support `if`/
# `case`, which this script needs to pick a MOJO_TEST_FEATURES default.
#
# CI always sets MOJO_TEST_FEATURES explicitly per-runner (see
# .github/workflows/ci.yml), so the fallback below never triggers there; it
# only kicks in for local/sandboxed runs where `mojo run`'s host-feature
# autodetection is unreliable (e.g. restricted containers).
set -e

if [ -z "$MOJO_TEST_FEATURES" ]; then
  case "$(uname -m)" in
    aarch64 | arm64)
      MOJO_TEST_FEATURES="--target-features=+neon,+aes"
      ;;
    *)
      MOJO_TEST_FEATURES="--target-features=+aes"
      ;;
  esac
fi

mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_aes.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_aes_cbc.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_aes_ctr.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_aes_gcm.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_aes_gcm_siv.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_aes_cmac.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/acvp/test_sha2.mojo

mojo run $MOJO_TEST_FEATURES -I . tests/block_ciphers/test_aes.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/block_ciphers/test_ctr.mojo

mojo run $MOJO_TEST_FEATURES -I . tests/universal_hashes/test_field_element.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/universal_hashes/test_polyval.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/universal_hashes/test_ghash.mojo

mojo run $MOJO_TEST_FEATURES -I . tests/macs/test_cmac.mojo

mojo run $MOJO_TEST_FEATURES -I . tests/hashes/test_sha2.mojo

mojo run $MOJO_TEST_FEATURES -I . tests/utils/test_hex.mojo
mojo run $MOJO_TEST_FEATURES -I . tests/utils/test_common.mojo
