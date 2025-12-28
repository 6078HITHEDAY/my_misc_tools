import base64
import binascii
import urllib.parse
from typing import List, Tuple

from .cultural_encodings import buddha_decode, core_values_decode
from .encoders import (
    base32_decode,
    base64_decode,
    base64url_decode,
    base16_decode,
    base85_decode,
    base58_decode,
    url_decode,
    unicode_escape_decode,
    html_entity_decode,
)
from .classical import rot13, atbash
from .base_utils import base45_decode, base62_decode, base91_decode


class AutoDecodeResult(Tuple[str, str]):
    """(method, decoded_text)"""


def _is_base64(text: str) -> bool:
    try:
        return base64.b64encode(base64.b64decode(text)).decode("ascii") == text
    except Exception:
        return False


def _is_base32(text: str) -> bool:
    try:
        base64.b32decode(text)
        return True
    except Exception:
        return False


def _is_hex(text: str) -> bool:
    try:
        bytes.fromhex(text)
        return True
    except Exception:
        return False


def _safe_decode_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("latin-1", errors="ignore")


def auto_decode(text: str) -> List[AutoDecodeResult]:
    """
    Try several lightweight decoders and return successful candidates.
    """
    candidates: List[AutoDecodeResult] = []

    # Base64
    if _is_base64(text):
        try:
            candidates.append(("base64", base64_decode(text)))
        except Exception:
            pass

    # Base32
    if _is_base32(text):
        try:
            candidates.append(("base32", base32_decode(text)))
        except Exception:
            pass

    # Base45 (URL-safe set with space and $%*+-./:)
    if all(ch in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:" for ch in text.strip()):
        try:
            decoded_bytes = base45_decode(text)
            candidates.append(("base45", _safe_decode_bytes(decoded_bytes)))
        except Exception:
            pass

    # Base64URL
    if all(ch.isalnum() or ch in "-_" for ch in text):
        try:
            decoded = base64url_decode(text)
            candidates.append(("base64url", decoded))
        except Exception:
            pass

    # Base16/hex -> ascii
    if _is_hex(text) and len(text) % 2 == 0:
        try:
            candidates.append(("hex", base16_decode(text)))
        except Exception:
            pass

    # URL decode
    if "%" in text or "+" in text:
        try:
            decoded = url_decode(text)
            if decoded != text:
                candidates.append(("url", decoded))
        except Exception:
            pass

    # Base85
    try:
        decoded = base85_decode(text)
        candidates.append(("base85", decoded))
    except Exception:
        pass

    # Base58 (heuristic: only alphabet)
    if all(ch in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for ch in text):
        try:
            decoded = base58_decode(text)
            candidates.append(("base58", decoded))
        except Exception:
            pass

    # Base62 (alnum only)
    if text and text.isalnum():
        try:
            decoded_bytes = base62_decode(text)
            candidates.append(("base62", _safe_decode_bytes(decoded_bytes)))
        except Exception:
            pass

    # Base91 (broad charset, fallback)
    if 4 <= len(text) <= 200:  # avoid spamming on very long text
        try:
            decoded_bytes = base91_decode(text)
            decoded_str = _safe_decode_bytes(decoded_bytes)
            if decoded_str != text:
                candidates.append(("base91", decoded_str))
        except Exception:
            pass

    # ROT13
    try:
        rot = rot13(text)
        if rot != text:
            candidates.append(("rot13", rot))
    except Exception:
        pass

    # Core values / Buddha
    try:
        decoded = core_values_decode(text)
        candidates.append(("core_values", decoded))
    except Exception:
        pass
    try:
        decoded = buddha_decode(text)
        candidates.append(("buddha", decoded))
    except Exception:
        pass

    # Atbash
    try:
        decoded = atbash(text)
        if decoded != text:
            candidates.append(("atbash", decoded))
    except Exception:
        pass

    # Unicode escape
    try:
        decoded = unicode_escape_decode(text)
        if decoded != text:
            candidates.append(("unicode_escape", decoded))
    except Exception:
        pass

    # HTML entities
    try:
        decoded = html_entity_decode(text)
        if decoded != text:
            candidates.append(("html_entity", decoded))
    except Exception:
        pass

    return candidates
