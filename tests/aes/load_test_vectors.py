from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class AesType(Enum):
    AES128 = 128
    AES192 = 192
    AES256 = 256

@dataclass
class TestData:
    aes_type: AesType
    key_hex: str
    pt_hex: str
    ct_hex: str
    file_name: str

    def is_aes_type(self, type: AesType) -> bool:
        return self.aes_type == type

def parse_rsp(path: Path) -> list[TestData]:
    records: list[TestData] = []
    key_hex = pt_hex = ct_hex = None

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line.startswith("KEY = "):
            key_hex = line.removeprefix("KEY = ")
        elif line.startswith("PLAINTEXT = "):
            pt_hex = line.removeprefix("PLAINTEXT = ")
        elif line.startswith("CIPHERTEXT = "):
            ct_hex = line.removeprefix("CIPHERTEXT = ")

        if key_hex and pt_hex and ct_hex:
            records.append(
                TestData(
                    aes_type=AesType(len(key_hex) * 4),
                    key_hex=key_hex,
                    pt_hex=pt_hex,
                    ct_hex=ct_hex,
                    file_name=path.name,
                )
            )
            key_hex = pt_hex = ct_hex = None

    return records


def load(dir: str) -> list[TestData]:
    root = Path(dir)
    vectors: list[TestData] = []
    for path in root.glob("ECB*.rsp"):
        vectors.extend(parse_rsp(path))
    return vectors


def print_vectors(vectors: list[TestData]) -> None:
    for v in vectors:
        print(v)
