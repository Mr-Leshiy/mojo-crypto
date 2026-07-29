#!/usr/bin/env bash
# Compile-only checks for the Mojo benchmarks: verify each backend builds
# without running it (running requires a GPU / specific host CPU). Wrapped in
# a real shell (rather than inlined in pixi.toml) for consistency with
# scripts/test.sh and to keep pixi.toml's task list readable.
set -e

out=$(mktemp -d)

mojo build --emit=asm -I . benchmarks/block_ciphers/aes/naive.mojo -o $out/aes_naive
mojo build --emit=asm --target-triple=aarch64-unknown-linux-gnu --target-features=+neon,+aes -I . benchmarks/block_ciphers/aes/aarch64.mojo -o $out/aes_aarch64
mojo build --emit=asm --target-triple=x86_64-unknown-linux-gnu --target-features=+aes,+sse2 -I . benchmarks/block_ciphers/aes/x86.mojo -o $out/aes_x86
mojo build --emit=asm --target-accelerator=sm_80 -I . benchmarks/block_ciphers/aes/gpu.mojo -o $out/aes_gpu

mojo build --emit=asm -I . benchmarks/universal_hashes/ghash/naive.mojo -o $out/ghash_naive
mojo build --emit=asm --target-triple=aarch64-unknown-linux-gnu --target-features=+neon,+aes -I . benchmarks/universal_hashes/ghash/aarch64.mojo -o $out/ghash_aarch64
mojo build --emit=asm --target-triple=x86_64-unknown-linux-gnu --target-features=+pclmul,+sse2 -I . benchmarks/universal_hashes/ghash/x86.mojo -o $out/ghash_x86
mojo build --emit=asm -I . benchmarks/universal_hashes/polyval/naive.mojo -o $out/polyval_naive
mojo build --emit=asm --target-triple=aarch64-unknown-linux-gnu --target-features=+neon,+aes -I . benchmarks/universal_hashes/polyval/aarch64.mojo -o $out/polyval_aarch64
mojo build --emit=asm --target-triple=x86_64-unknown-linux-gnu --target-features=+pclmul,+sse2 -I . benchmarks/universal_hashes/polyval/x86.mojo -o $out/polyval_x86

rm -rf $out
