#!/usr/bin/env bash
# Runs the Mojo test suite: every tests/**/test_*.mojo file, in sorted order.
#
# The hardware backends are compiled in only when their CPU features are
# enabled, so the caller decides which ones to build via $MOJO_TEST_FEATURES: a
# space-separated list of `mojo run` flags, e.g.
# "--target-features=+neon,+aes,+sha2". CI sets it per-runner (see
# .github/workflows/ci.yml). Nothing is defaulted here — when it is unset the
# tests build for whatever `mojo run` autodetects on the host, which still
# covers the naive backends.
set -e -o pipefail

# Word-split into an array so multiple flags work and an unset/empty value
# contributes no arguments at all.
read -r -a features <<<"${MOJO_TEST_FEATURES-}"

failed=()
while IFS= read -r test; do
  echo "==> mojo run ${MOJO_TEST_FEATURES-} -I . $test"
  if ! mojo run "${features[@]}" -I . "$test"; then
    failed+=("$test")
  fi
done < <(find tests -name 'test_*.mojo' | sort)

if [ ${#failed[@]} -ne 0 ]; then
  echo
  echo "${#failed[@]} test file(s) failed:"
  printf '  %s\n' "${failed[@]}"
  exit 1
fi
