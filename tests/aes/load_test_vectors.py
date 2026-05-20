from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class AesMode(Enum):
    ECB = "ECB"      # Electronic Codebook: each block encrypted independently, no IV
    CBC = "CBC"      # Cipher Block Chaining: XOR with previous ciphertext block, requires IV
    CFB1 = "CFB1"    # Cipher Feedback (1-bit segments): stream cipher variant, 1-bit feedback
    CFB8 = "CFB8"    # Cipher Feedback (8-bit segments): stream cipher variant, 8-bit feedback
    CFB128 = "CFB128"  # Cipher Feedback (128-bit segments): stream cipher variant, full block
    OFB = "OFB"      # Output Feedback: keystream independent of plaintext, no error propagation
    CTR = "CTR"      # Counter: encrypts incrementing nonce+counter, fully parallelizable


class AesType(Enum):
    AES128 = 128
    AES192 = 192
    AES256 = 256


@dataclass
class TestData:
    is_encrypt: bool
    aes_type: AesType
    key_hex: str
    pt_hex: str
    ct_hex: str
    file_name: str


def parse_rsp(path: Path) -> list[TestData]:
    records: list[TestData] = []
    is_encrypt = True
    key_hex = pt_hex = ct_hex = None

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line == "[ENCRYPT]":
            is_encrypt = True
        elif line == "[DECRYPT]":
            is_encrypt = False
        elif line.startswith("KEY = "):
            key_hex = line.removeprefix("KEY = ")
        elif line.startswith("PLAINTEXT = "):
            pt_hex = line.removeprefix("PLAINTEXT = ")
        elif line.startswith("CIPHERTEXT = "):
            ct_hex = line.removeprefix("CIPHERTEXT = ")

        if key_hex and pt_hex and ct_hex:
            records.append(
                TestData(
                    is_encrypt=is_encrypt,
                    aes_type=AesType(len(key_hex) * 4),
                    key_hex=key_hex,
                    pt_hex=pt_hex,
                    ct_hex=ct_hex,
                    file_name=path.name,
                )
            )
            key_hex = pt_hex = ct_hex = None

    return records


def load(dir: str, mode: AesMode = AesMode.ECB) -> list[TestData]:
    root = Path(dir)
    vectors: list[TestData] = []
    for path in root.glob(f"{mode.value}*.rsp"):
        vectors.extend(parse_rsp(path))
    return vectors

