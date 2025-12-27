import base64
from typing import Dict, List

# Socialist core values mapping for hex digits (16 symbols).
CORE_VALUES = [
    "富强",
    "民主",
    "文明",
    "和谐",
    "自由",
    "平等",
    "公正",
    "法治",
    "爱国",
    "敬业",
    "诚信",
    "友善",
    "富民",
    "爱民",
    "敬老",
    "友邻",
]

HEX_TO_VALUES: Dict[str, str] = {hex_digit: CORE_VALUES[idx] for idx, hex_digit in enumerate("0123456789abcdef")}
VALUES_TO_HEX: Dict[str, str] = {value: hex_digit for hex_digit, value in HEX_TO_VALUES.items()}

# Buddha-style encoding: custom base64 alphabet mapped to Buddhist-flavored tokens.
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BUDDHA_PREFIX = ["阿", "弥", "陀", "佛", "如", "来", "若", "空"]
_BUDDHA_SUFFIX = ["若", "色", "空", "识", "心", "意", "戒", "定"]
BUDDHA_TOKENS: List[str] = [f"佛曰{p}{s}" for p in _BUDDHA_PREFIX for s in _BUDDHA_SUFFIX]
BUDDHA_PAD = "佛曰止"
B64_TO_BUDDHA: Dict[str, str] = {ch: token for ch, token in zip(B64_ALPHABET, BUDDHA_TOKENS)}
B64_TO_BUDDHA["="] = BUDDHA_PAD
BUDDHA_TO_B64: Dict[str, str] = {token: ch for ch, token in B64_TO_BUDDHA.items()}


def core_values_encode(text: str) -> str:
    """
    Encode UTF-8 text to hex, then map each hex digit to a core value phrase.
    """
    hexed = text.encode("utf-8").hex()
    return " ".join(HEX_TO_VALUES[digit] for digit in hexed)


def core_values_decode(code: str) -> str:
    """
    Decode a core values encoded string back to text.
    """
    tokens = [token for token in code.strip().split() if token]
    try:
        hex_str = "".join(VALUES_TO_HEX[token] for token in tokens)
    except KeyError as exc:
        raise ValueError(f"Unrecognized core value token: {exc.args[0]}") from exc
    return bytes.fromhex(hex_str).decode("utf-8")


def buddha_encode(text: str) -> str:
    """
    Encode text with a Buddha-style mapper on top of Base64.
    """
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return " ".join(B64_TO_BUDDHA[ch] for ch in b64)


def buddha_decode(code: str) -> str:
    """
    Decode Buddha-style text back to the original string.
    """
    tokens = [token for token in code.strip().split() if token]
    try:
        b64 = "".join(BUDDHA_TO_B64[token] for token in tokens)
    except KeyError as exc:
        raise ValueError(f"Unrecognized Buddha token: {exc.args[0]}") from exc
    return base64.b64decode(b64).decode("utf-8")
