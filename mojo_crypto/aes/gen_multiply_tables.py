#!/usr/bin/env python3
"""Generate mojo_crypto/aes/ml_tables.mojo with precomputed AES lookup tables.

Run with:
    python mojo_crypto/aes/gen_multiply_tables
"""

from pathlib import Path


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic
# ---------------------------------------------------------------------------

def _xtime(a: int) -> int:
    result = (a << 1) & 0xFF
    if a & 0x80:
        result ^= 0x1B
    return result


def _gf_mul(a: int, b: int) -> int:
    result = 0
    factor = b
    scalar = a
    while scalar:
        if scalar & 1:
            result ^= factor
        factor = _xtime(factor)
        scalar >>= 1
    return result



# ---------------------------------------------------------------------------
# Table computation
# ---------------------------------------------------------------------------

MUL2  = [_gf_mul(0x02, i) for i in range(256)]
MUL3  = [_gf_mul(0x03, i) for i in range(256)]
MUL9  = [_gf_mul(0x09, i) for i in range(256)]
MUL11 = [_gf_mul(0x0B, i) for i in range(256)]
MUL13 = [_gf_mul(0x0D, i) for i in range(256)]
MUL14 = [_gf_mul(0x0E, i) for i in range(256)]

TABLES: list[tuple[str, list[int], str]] = [
    ("MUL2",    MUL2,    "GF(2^8) multiply by 0x02 (xtime) — MixColumns"),
    ("MUL3",    MUL3,    "GF(2^8) multiply by 0x03 — MixColumns"),
    ("MUL9",    MUL9,    "GF(2^8) multiply by 0x09 — InvMixColumns"),
    ("MUL11",   MUL11,   "GF(2^8) multiply by 0x0B — InvMixColumns"),
    ("MUL13",   MUL13,   "GF(2^8) multiply by 0x0D — InvMixColumns"),
    ("MUL14",   MUL14,   "GF(2^8) multiply by 0x0E — InvMixColumns"),
]


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------

HEADER = """\
# AUTO-GENERATED — do not edit by hand.
# Re-generate with: python mojo_crypto/aes/gen_multiply_tables.py
"""


def _fmt_table(name: str, table: list[int], doc: str) -> str:
    rows = []
    for i in range(0, 256, 16):
        row = ", ".join(f"0x{v:02x}" for v in table[i : i + 16])
        rows.append(f"    {row},")
    body = "\n".join(rows)
    return (
        f"# {doc}\n"
        f"comptime {name}: InlineArray[UInt8, 256] = [\n"
        f"    # fmt: off\n"
        f"{body}\n"
        f"    # fmt: on\n"
        f"]\n"
    )


def main() -> None:
    out = Path(__file__).with_name("ml_tables.mojo")
    with out.open("w") as f:
        f.write(HEADER)
        for name, table, doc in TABLES:
            f.write("\n")
            f.write(_fmt_table(name, table, doc))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
