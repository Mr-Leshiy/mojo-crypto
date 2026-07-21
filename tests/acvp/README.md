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

## Test types

- **AFT** (Algorithm Functional Test) — independent key/plaintext/ciphertext
  vectors, each checked in isolation.
- **MCT** (Monte Carlo Test) — a chained ~1000-iteration loop per seed, with
  the key itself mutated periodically per [AESAVS §6.4.1](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf);
  only 100 checkpoint snapshots are given in `resultsArray`, so the
  implementation must reproduce the inner loop to match them.

## Vector sets

| Directory | Mode | Test file |
| --- | --- | --- |
| `ACVP-AES-ECB-1.0` | ECB | `test_aes.mojo` |
| `ACVP-AES-CBC-1.0` | CBC | `test_aes_cbc.mojo` |
| `ACVP-AES-CTR-1.0` | CTR | `test_aes_ctr.mojo` |
| `ACVP-AES-GCM-SIV-1.0` | GCM-SIV | `test_aes_gcm_siv.mojo` |
| `CMAC-AES-1.0` | CMAC (OMAC1) | `test_aes_cmac.mojo` |
| `ACVP-AES-GCM-1.0` | GCM | not yet covered |
