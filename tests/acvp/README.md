# ACVP tests

Tests in this directory validate the implementations in `mojo_crypto/` against
test vectors from NIST's [Automated Cryptographic Validation Protocol (ACVP)](https://pages.nist.gov/ACVP/),
sourced from the [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
`gen-val/json-files` reference vectors.

Each vector set under `data/` was downloaded as three JSON files:

- `prompt.json` — test groups/cases (keys, plaintext/ciphertext, IVs, etc.)
- `expectedResults.json` — the expected output for each test case, keyed by `tcId`
- `registration.json` — the algorithm/mode parameters used to request the vector set

`internalProjection.json` and `validation.json` are also included per vector
set but are not consumed by these tests.

Vectors are parsed by `read_acvp_vectors.py` and bridged into Mojo via
`utils.mojo`'s `load_python_acvp_vectors`, which merges each test case with
its expected result before handing it to the Mojo-side parser in the
corresponding `test_*.mojo` file.

## Vector sets

| Directory | Mode | Test file |
| --- | --- | --- |
| `ACVP-AES-ECB-1.0` | ECB | `test_aes.mojo` |
| `ACVP-AES-CBC-1.0` | CBC | `test_aes_cbc.mojo` |
| `ACVP-AES-CTR-1.0` | CTR | `test_aes_ctr.mojo` |
| `ACVP-AES-GCM-SIV-1.0` | GCM-SIV | `test_aes_gcm_siv.mojo` |
| `CMAC-AES-1.0` | CMAC (OMAC1) | `test_aes_cmac.mojo` |
| `ACVP-AES-GCM-1.0` | GCM | not yet covered |
| `SHA2-224-1.0` | SHA-224 | `test_sha2.mojo` |
| `SHA2-256-1.0` | SHA-256 | `test_sha2.mojo` |
| `SHA2-384-1.0` | SHA-384 | `test_sha2.mojo` |
| `SHA2-512-1.0` | SHA-512 | `test_sha2.mojo` |
| `SHA2-512-224-1.0` | SHA-512/224 | `test_sha2.mojo` |
| `SHA2-512-256-1.0` | SHA-512/256 | `test_sha2.mojo` |
| `HMAC-SHA2-224-1.0` | HMAC-SHA-224 | `test_hmac.mojo` |
| `HMAC-SHA2-256-1.0` | HMAC-SHA-256 | `test_hmac.mojo` |
| `HMAC-SHA2-384-1.0` | HMAC-SHA-384 | `test_hmac.mojo` |
| `HMAC-SHA2-512-1.0` | HMAC-SHA-512 | `test_hmac.mojo` |
| `HMAC-SHA2-512-224-1.0` | HMAC-SHA-512/224 | `test_hmac.mojo` |
| `HMAC-SHA2-512-256-1.0` | HMAC-SHA-512/256 | `test_hmac.mojo` |
| `SHA3-224-2.0` | SHA3-224 | `test_sha3.mojo` |
| `SHA3-256-2.0` | SHA3-256 | `test_sha3.mojo` |
| `SHA3-384-2.0` | SHA3-384 | `test_sha3.mojo` |
| `SHA3-512-2.0` | SHA3-512 | `test_sha3.mojo` |
| `SHAKE-128-1.0` | SHAKE-128 (bit-oriented) | `test_sha3.mojo` |
| `SHAKE-256-1.0` | SHAKE-256 (bit-oriented) | `test_sha3.mojo` |
| `SHAKE-128-FIPS202` | SHAKE-128 (byte-aligned) | `test_sha3.mojo` |
| `SHAKE-256-FIPS202` | SHAKE-256 (byte-aligned) | `test_sha3.mojo` |
| `HMAC-SHA3-224-2.0` | HMAC-SHA3-224 | `test_hmac.mojo` |
| `HMAC-SHA3-256-2.0` | HMAC-SHA3-256 | `test_hmac.mojo` |
| `HMAC-SHA3-384-2.0` | HMAC-SHA3-384 | `test_hmac.mojo` |
| `HMAC-SHA3-512-2.0` | HMAC-SHA3-512 | `test_hmac.mojo` |

SHA-2 AFT vectors with a non-byte-aligned bit length (allowed for
SHA-224/384/512-224, whose registration permits bit-granular
`messageLength`) are skipped: `Digest.update` only consumes whole bytes, so
there's no way to feed a message ending mid-byte.

The HMAC sets define AFT groups only, all byte-aligned. Their `macLen` runs
80..160 bits — always shorter than the digest — so `test_hmac.mojo` compares
only that many leading bytes of the computed tag, as `test_aes_cmac.mojo`
does for CMAC. Keys run 8..2048 bits, covering both `K0` derivations: keys
shorter than the hash block (zero-padded) and longer than it (hashed down
first).

`SHA3-*-2.0` allows bit-granular `messageLength` (increment 1), the same as
the SHA-2 sets, so the same byte-alignment skip applies. Each set also
defines an `LDT` (large-data) group, which is skipped entirely: its smallest
message is 1 GiB (`fullLength`, built by repeating a short `content` pattern
up to that size), far too slow to hash in a test run against the naive
backend — the only one SHA-3 has today. `MCT` groups (each round rehashes
the previous digest directly — `MSG = MD[i-1]`, no `A || B || C`
concatenation like SHA-2's) support both the `standard` and `alternate`
chaining rules, though the downloaded vectors only exercise `standard`;
`alternate`'s length normalization is a no-op for fixed-output SHA-3, whose
digest is always exactly one seed-width wide.

`SHAKE-*-1.0` is the bit-oriented revision (registration sets `inBit`/
`outBit`, with `outputLen` increment 1) and `SHAKE-*-FIPS202` is the newer
byte-aligned-only revision (`messageLength`/`outputLen` increment 8) — both
are included since neither supersedes the other in the upstream repo. Test
cases in both use the same `msg`/`len`/`outLen` fields regardless of
revision; for `-1.0`, vectors whose message length *or* output length
doesn't land on a byte boundary are skipped, for the same reason as SHA-2/
SHA-3's message-length skip — `Xof.update`/`squeeze` only ever consume or
produce whole bytes. `SHAKE-*-1.0` additionally defines `VOT` (Variable
Output Test) groups — AFT-shaped vectors that vary `outLen` per test case
instead of holding it fixed — and `MCT` groups, whose algorithm is not the
same recurrence as SHA-3's: the output length itself changes every one of
the 1000 inner rounds (`OutputLen = minOutBytes + (rightmost 16 bits of the
round's digest mod Range)`, persisting across all 100 outer rounds rather
than resetting). That recurrence was verified against the downloaded
`SHAKE-128-1.0` vectors with a standalone `openssl`-based simulation before
being implemented in Mojo, since the ACVP pseudocode's exact ordering is
easy to misread. `SHAKE-*-FIPS202` defines `AFT` groups only.

`HMAC-SHA3-*-2.0` was used over `-1.0` since it's a strict superset (adds a
`msgLen` parameter). Adding these vectors surfaced a real bug in `Hmac`
itself, not just a test gap: its key-padding XOR reinterpreted a
`BLOCK_SIZE`-lane `SIMD[uint8]` as a `BLOCK_SIZE`-byte array, which only held
for SHA-2's power-of-two block sizes (64/128) — a `SIMD` vector's storage is
padded up to the next power of two, so the same trick silently broke for
SHA-3's Keccak rates (144/136/104/72), which aren't. Fixed in
`mojo_crypto/macs/hmac.mojo` by XORing the pad byte in a plain byte loop
instead of via `SIMD`.
