# ACVP tests

Tests in this directory validate the implementations in `mojo_crypto/` against
test vectors from NIST's [Automated Cryptographic Validation Protocol (ACVP)](https://pages.nist.gov/ACVP/),
sourced from the [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
`gen-val/json-files` reference vectors.

Each vector set under `data/` was downloaded as up to five JSON files —
`internalProjection.json`/`validation.json` are only present for some sets
(currently the AES ones, plus `validation.json` for `CMAC-AES-1.0`):

| File | Description | Used |
| --- | --- | --- |
| `prompt.json` | Test groups/cases — keys, plaintext/ciphertext, IVs, etc. | True |
| `expectedResults.json` | The expected output for each test case, keyed by `tcId` | True |
| `registration.json` | The algorithm/mode parameters used to request the vector set | True |
| `internalProjection.json` | `prompt.json` and `expectedResults.json` pre-merged into one file, plus NIST-internal-only fields (e.g. `internalTestType`) | False |
| `validation.json` | A pass/fail disposition per `tcId` from NIST's own reference run — a result record, not test data | False |

Vectors are parsed by `read_acvp_vectors.py` and bridged into Mojo via
`utils.mojo`'s `load_python_acvp_vectors`, which merges each test case with
its expected result before handing it to the Mojo-side parser in the
corresponding `test_*.mojo` file.

## Vector sets

| Directory | Mode | Test file | testtypes.adoc |
| --- | --- | --- | --- |
| `ACVP-AES-ECB-1.0` | ECB | `test_aes.mojo` | [symmetric] |
| `ACVP-AES-CBC-1.0` | CBC | `test_aes_cbc.mojo` | [symmetric] |
| `ACVP-AES-CTR-1.0` | CTR | `test_aes_ctr.mojo` | [symmetric] |
| `ACVP-AES-GCM-SIV-1.0` | GCM-SIV | `test_aes_gcm_siv.mojo` | [symmetric] |
| `CMAC-AES-1.0` | CMAC (OMAC1) | `test_aes_cmac.mojo` | [mac] |
| `ACVP-AES-GCM-1.0` | GCM | not yet covered | [symmetric] |
| `SHA2-224-1.0` | SHA-224 | `test_sha2.mojo` | [sha] |
| `SHA2-256-1.0` | SHA-256 | `test_sha2.mojo` | [sha] |
| `SHA2-384-1.0` | SHA-384 | `test_sha2.mojo` | [sha] |
| `SHA2-512-1.0` | SHA-512 | `test_sha2.mojo` | [sha] |
| `SHA2-512-224-1.0` | SHA-512/224 | `test_sha2.mojo` | [sha] |
| `SHA2-512-256-1.0` | SHA-512/256 | `test_sha2.mojo` | [sha] |
| `HMAC-SHA2-224-1.0` | HMAC-SHA-224 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA2-256-1.0` | HMAC-SHA-256 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA2-384-1.0` | HMAC-SHA-384 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA2-512-1.0` | HMAC-SHA-512 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA2-512-224-1.0` | HMAC-SHA-512/224 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA2-512-256-1.0` | HMAC-SHA-512/256 | `test_hmac.mojo` | [mac] |
| `SHA3-224-2.0` | SHA3-224 | `test_sha3.mojo` | [sha3] |
| `SHA3-256-2.0` | SHA3-256 | `test_sha3.mojo` | [sha3] |
| `SHA3-384-2.0` | SHA3-384 | `test_sha3.mojo` | [sha3] |
| `SHA3-512-2.0` | SHA3-512 | `test_sha3.mojo` | [sha3] |
| `SHAKE-128-1.0` | SHAKE-128 (bit-oriented) | `test_sha3.mojo` | [sha3] |
| `SHAKE-256-1.0` | SHAKE-256 (bit-oriented) | `test_sha3.mojo` | [sha3] |
| `SHAKE-128-FIPS202` | SHAKE-128 (byte-aligned) | `test_sha3.mojo` | [sha3] |
| `SHAKE-256-FIPS202` | SHAKE-256 (byte-aligned) | `test_sha3.mojo` | [sha3] |
| `HMAC-SHA3-224-2.0` | HMAC-SHA3-224 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA3-256-2.0` | HMAC-SHA3-256 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA3-384-2.0` | HMAC-SHA3-384 | `test_hmac.mojo` | [mac] |
| `HMAC-SHA3-512-2.0` | HMAC-SHA3-512 | `test_hmac.mojo` | [mac] |

[symmetric]: https://github.com/usnistgov/ACVP/blob/master/src/symmetric/sections/04-testtypes.adoc
[mac]: https://github.com/usnistgov/ACVP/blob/master/src/mac/sections/04-testtypes.adoc
[sha]: https://github.com/usnistgov/ACVP/blob/master/src/sha/sections/04-testtypes.adoc
[sha3]: https://github.com/usnistgov/ACVP/blob/master/src/sha3/sections/04-testtypes.adoc

