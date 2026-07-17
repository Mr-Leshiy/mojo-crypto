import json
from enum import Enum
from pathlib import Path


class TestType(Enum):
    # Algorithm Functional Test: independent key/pt/ct vectors, checked in isolation.
    AFT = "AFT"
    # Monte Carlo Test: a chained ~1000-iteration loop per seed, with the key
    # itself mutated periodically; only 100 checkpoint snapshots are given in
    # resultsArray, so the implementation must reproduce the inner loop.
    MCT = "MCT"


def _result_index(expected: dict) -> dict[int, dict]:
    index: dict[int, dict] = {}
    for group in expected.get("testGroups", []):
        for tc in group.get("tests", []):
            index[tc["tcId"]] = tc
    return index


def load(dir: str, test_type: TestType) -> list[dict]:
    # No AFT/MCT-specific field extraction or renaming (pt_hex/ct_hex/
    # is_encrypt/...): each record is just the raw group, test-case, and
    # expected-result dicts as read from JSON, keyed by tcId. Interpretation
    # of these fields happens on the Mojo side.
    root = Path(dir)
    prompt = json.loads((root / "prompt.json").read_text())
    expected = json.loads((root / "expectedResults.json").read_text())
    results = _result_index(expected)

    records: list[dict] = []
    for group in prompt.get("testGroups", []):
        if group["testType"] != test_type.value:
            continue
        group_fields = {k: v for k, v in group.items() if k != "tests"}
        for tc in group["tests"]:
            records.append({
                "group": group_fields,
                "test": tc,
                "expected": results.get(tc["tcId"], {}),
            })
    return records
