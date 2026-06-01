import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class TestType(Enum):
    AFT = "AFT"
    MCT = "MCT"


@dataclass
class TestData:
    is_encrypt: bool
    key_len: int
    count: int
    key_hex: str
    iv_hex: str | None
    pt_hex: str
    ct_hex: str
    test_type: TestType


def _result_index(expected: dict) -> dict[int, dict]:
    index: dict[int, dict] = {}
    for group in expected.get("testGroups", []):
        for tc in group.get("tests", []):
            index[tc["tcId"]] = tc
    return index


def _parse_aft(group: dict, results: dict[int, dict]) -> list[TestData]:
    is_encrypt = group["direction"] == "encrypt"
    records: list[TestData] = []

    for tc in group["tests"]:
        expected = results.get(tc["tcId"], {})
        if is_encrypt:
            pt_hex, ct_hex = tc["pt"], expected.get("ct", "")
        else:
            ct_hex, pt_hex = tc["ct"], expected.get("pt", "")

        records.append(TestData(
            is_encrypt=is_encrypt,
            key_len=group["keyLen"],
            count=tc["tcId"],
            key_hex=tc["key"],
            iv_hex=tc.get("iv"),
            pt_hex=pt_hex,
            ct_hex=ct_hex,
            test_type=TestType.AFT,
        ))

    return records


def _parse_mct(group: dict, results: dict[int, dict]) -> list[TestData]:
    is_encrypt = group["direction"] == "encrypt"
    assert len(group["tests"]) == 1
    expected = results.get(group["tests"][0]["tcId"], {})

    return [
        TestData(
            is_encrypt=is_encrypt,
            key_len=group["keyLen"],
            count=i,
            key_hex=entry["key"],
            iv_hex=entry.get("iv"),
            pt_hex=entry["pt"],
            ct_hex=entry["ct"],
            test_type=TestType.MCT,
        )
        for i, entry in enumerate(expected.get("resultsArray", []))
    ]


def load(dir: str, test_type: TestType) -> list[TestData]:
    root = Path(dir)
    prompt = json.loads((root / "prompt.json").read_text())
    expected = json.loads((root / "expectedResults.json").read_text())
    results = _result_index(expected)

    records: list[TestData] = []
    for group in prompt.get("testGroups", []):
        if group["testType"] == "AFT":
            records.extend(_parse_aft(group, results))
        elif group["testType"] == "MCT":
            records.extend(_parse_mct(group, results))

    return [v for v in records if v.test_type == test_type]
