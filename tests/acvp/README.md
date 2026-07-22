# ACVP tests

Tests in this directory validate the AES implementation against test vectors
from NIST's [Automated Cryptographic Validation Protocol (ACVP)](https://pages.nist.gov/ACVP/),
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

SHA-2 AFT vectors with a non-byte-aligned bit length (allowed for
SHA-224/384/512-224, whose registration permits bit-granular
`messageLength`) are skipped: `Digest.update` only consumes whole bytes, so
there's no way to feed a message ending mid-byte.
