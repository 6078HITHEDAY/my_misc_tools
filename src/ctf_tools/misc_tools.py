import quopri
import hashlib
import binascii
from typing import Dict, Literal, Optional, Tuple

from .modern_crypto import DataFormat, _load_bytes

BASE_ALLOWED = {2, 8, 10, 16}
PRINTABLE_ASCII = "".join(chr(i) for i in range(32, 127))

# Bacon cipher mapping (classic, I/J and U/V merged)
BACON_ALPHABET = [
    "AAAAA",
    "AAAAB",
    "AAABA",
    "AAABB",
    "AABAA",
    "AABAB",
    "AABBA",
    "AABBB",
    "ABAAA",
    "ABAAB",
    "ABABA",
    "ABABB",
    "ABBAA",
    "ABBAB",
    "ABBBA",
    "ABBBB",
    "BAAAA",
    "BAAAB",
    "BAABA",
    "BAABB",
    "BABAA",
    "BABAB",
    "BABBA",
    "BABBB",
]

BACON_CHAR_MAP: Dict[str, str] = {}
BACON_REVERSE_MAP: Dict[str, str] = {}

for idx, pattern in enumerate(BACON_ALPHABET):
    letter = chr(ord("A") + idx)
    if letter == "J":
        BACON_CHAR_MAP[letter] = BACON_CHAR_MAP["I"]
        continue
    if letter == "V":
        BACON_CHAR_MAP[letter] = BACON_CHAR_MAP["U"]
        continue
    BACON_CHAR_MAP[letter] = pattern
    BACON_REVERSE_MAP[pattern] = letter

# Pigpen cipher mapping using ASCII-friendly tokens.
PIGPEN_MAP: Dict[str, str] = {
    "A": "TL",
    "B": "T",
    "C": "TR",
    "D": "L",
    "E": "C",
    "F": "R",
    "G": "BL",
    "H": "B",
    "I": "BR",
    "J": "TL.",
    "K": "T.",
    "L": "TR.",
    "M": "L.",
    "N": "C.",
    "O": "R.",
    "P": "BL.",
    "Q": "B.",
    "R": "BR.",
    "S": "XTL",
    "T": "XTR",
    "U": "XBL",
    "V": "XBR",
    "W": "XTL.",
    "X": "XTR.",
    "Y": "XBL.",
    "Z": "XBR.",
}

PIGPEN_REVERSE_MAP: Dict[str, str] = {v: k for k, v in PIGPEN_MAP.items()}

HashName = Literal["md5", "sha1", "sha224", "sha256", "sha512", "crc32"]


def convert_base(value: str, from_base: int, to_base: int) -> str:
    if from_base not in BASE_ALLOWED or to_base not in BASE_ALLOWED:
        raise ValueError(f"Bases must be one of {sorted(BASE_ALLOWED)}.")
    number = int(value, from_base)
    if to_base == 10:
        return str(number)
    if to_base == 2:
        return bin(number)[2:]
    if to_base == 8:
        return oct(number)[2:]
    if to_base == 16:
        return hex(number)[2:]
    raise ValueError(f"Unsupported base: {to_base}")


def hash_data(
    data: str, algorithm: HashName = "md5", input_format: DataFormat = "utf8"
) -> str:
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha224": hashlib.sha224,
        "crc32": lambda: _CRC32(),
    }
    if algorithm not in algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    digest = algorithms[algorithm]()
    digest.update(_load_bytes(data, input_format))
    return digest.hexdigest()


def bacon_encode(message: str) -> str:
    encoded_bits = []
    for char in message.upper():
        if char == " ":
            encoded_bits.append("/")  # word separator
            continue
        if char == "J":
            char = "I"
        if char == "V":
            char = "U"
        if char not in BACON_CHAR_MAP:
            raise ValueError(f"Unsupported character for Bacon cipher: {char}")
        encoded_bits.append(BACON_CHAR_MAP[char])
    return " ".join(encoded_bits)


def bacon_decode(code: str) -> str:
    words = []
    for word in code.split("/"):
        letters = []
        for token in word.strip().split():
            if not token:
                continue
            if token not in BACON_REVERSE_MAP:
                raise ValueError(f"Invalid Bacon pattern: {token}")
            letters.append(BACON_REVERSE_MAP[token])
        words.append("".join(letters))
    return " ".join(words)


def pigpen_encode(message: str) -> str:
    tokens = []
    for char in message.upper():
        if char == " ":
            tokens.append("/")
            continue
        if char not in PIGPEN_MAP:
            raise ValueError(f"Unsupported character for Pigpen cipher: {char}")
        tokens.append(PIGPEN_MAP[char])
    return " ".join(tokens)


def pigpen_decode(code: str) -> str:
    words = []
    for word in code.split("/"):
        letters = []
        for token in word.strip().split():
            if not token:
                continue
            if token not in PIGPEN_REVERSE_MAP:
                raise ValueError(f"Invalid Pigpen token: {token}")
            letters.append(PIGPEN_REVERSE_MAP[token])
        words.append("".join(letters))
    return " ".join(words)


def quoted_printable_encode(text: str, input_format: DataFormat = "utf8") -> str:
    raw = _load_bytes(text, input_format)
    return quopri.encodestring(raw).decode("ascii")


def quoted_printable_decode(data: str, output_format: DataFormat = "utf8") -> str:
    decoded = quopri.decodestring(data)
    return decoded.decode("utf-8") if output_format == "utf8" else _dump(decoded, output_format)


def uu_encode(text: str, input_format: DataFormat = "utf8") -> str:
    data = _load_bytes(text, input_format)
    return binascii.b2a_uu(data).decode("ascii")


def uu_decode(data: str, output_format: DataFormat = "utf8") -> str:
    decoded = binascii.a2b_uu(data)
    return _dump(decoded, output_format)


def hex_to_ascii(hex_str: str) -> str:
    """Convert hex string to ASCII text."""
    return bytes.fromhex(hex_str).decode("latin-1")


def bin_to_ascii(bin_str: str) -> str:
    """Convert space-separated or continuous binary string to ASCII text."""
    cleaned = bin_str.replace(" ", "")
    if len(cleaned) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8.")
    bytes_list = [int(cleaned[i : i + 8], 2) for i in range(0, len(cleaned), 8)]
    return bytes(bytes_list).decode("latin-1")


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Key must not be empty.")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_cipher(
    text: str,
    key: str,
    input_format: DataFormat = "utf8",
    key_format: DataFormat = "utf8",
    output_format: DataFormat = "hex",
) -> str:
    data = _load_bytes(text, input_format)
    key_bytes = _load_bytes(key, key_format)
    result = xor_bytes(data, key_bytes)
    return _dump(result, output_format)


def xor_bruteforce_single_byte(data: bytes) -> Tuple[int, bytes]:
    """
    Try single-byte XOR keys and return the key with highest printable ratio.
    """
    best_score = -1.0
    best_key = 0
    best_plain = b""
    for key in range(256):
        plain = bytes(b ^ key for b in data)
        score = sum((32 <= c < 127) for c in plain) / max(1, len(plain))
        if score > best_score:
            best_score = score
            best_key = key
            best_plain = plain
    return best_key, best_plain


class _CRC32:
    """hashlib-like wrapper for CRC32 checksum."""

    def __init__(self) -> None:
        self._value = 0

    def update(self, data: bytes) -> None:
        self._value = binascii.crc32(data, self._value)

    def hexdigest(self) -> str:
        return f"{self._value & 0xFFFFFFFF:08x}"


def _dump(data: bytes, fmt: DataFormat) -> str:
    if fmt == "utf8":
        return data.decode("utf-8")
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        import base64 as _b64

        return _b64.b64encode(data).decode("ascii")
    raise ValueError(f"Unsupported format: {fmt}")
