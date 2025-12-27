import base64
import binascii
import urllib.parse
import html
import codecs

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base64_encode(data: str, encoding: str = "utf-8") -> str:
    """Encode text to Base64 using the provided character encoding."""
    return base64.b64encode(data.encode(encoding)).decode("ascii")


def base64_decode(encoded: str, encoding: str = "utf-8") -> str:
    """Decode Base64 text into a string using the provided character encoding."""
    return base64.b64decode(encoded.encode("ascii")).decode(encoding)


def base32_encode(data: str, encoding: str = "utf-8") -> str:
    """Encode text to Base32 using the provided character encoding."""
    return base64.b32encode(data.encode(encoding)).decode("ascii")


def base32_decode(encoded: str, encoding: str = "utf-8") -> str:
    """Decode Base32 text into a string using the provided character encoding."""
    return base64.b32decode(encoded.encode("ascii")).decode(encoding)


def base64url_encode(data: str, encoding: str = "utf-8") -> str:
    """Encode text to Base64URL (no padding)."""
    return base64.urlsafe_b64encode(data.encode(encoding)).rstrip(b"=").decode("ascii")


def base64url_decode(encoded: str, encoding: str = "utf-8") -> str:
    """Decode Base64URL text (padding optional)."""
    padded = encoded + "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode(encoding)


def base16_encode(data: str, encoding: str = "utf-8") -> str:
    """Encode text to Base16/Hex."""
    return binascii.hexlify(data.encode(encoding)).decode("ascii")


def base16_decode(encoded: str, encoding: str = "utf-8") -> str:
    """Decode Base16/Hex into text."""
    return binascii.unhexlify(encoded.encode("ascii")).decode(encoding)


def base58_encode(data: str, encoding: str = "utf-8") -> str:
    """
    Encode text to Base58 (Bitcoin alphabet).
    """
    num = int.from_bytes(data.encode(encoding), "big")
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = BASE58_ALPHABET[rem] + result
    # preserve leading zeros
    pad = 0
    for b in data.encode(encoding):
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + result


def base58_decode(encoded: str, encoding: str = "utf-8") -> str:
    """
    Decode Base58 (Bitcoin alphabet) text to string.
    """
    num = 0
    for ch in encoded:
        num *= 58
        if ch not in BASE58_ALPHABET:
            raise ValueError("Invalid Base58 character")
        num += BASE58_ALPHABET.index(ch)
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big") or b"\x00"
    # handle leading '1's as zero bytes
    n_pad = len(encoded) - len(encoded.lstrip("1"))
    decoded = b"\x00" * n_pad + combined
    return decoded.lstrip(b"\x00").decode(encoding, errors="ignore")


def base85_encode(data: str, encoding: str = "utf-8") -> str:
    return base64.a85encode(data.encode(encoding)).decode("ascii")


def base85_decode(encoded: str, encoding: str = "utf-8") -> str:
    return base64.a85decode(encoded.encode("ascii")).decode(encoding)


def url_encode(data: str, safe: str = "") -> str:
    """
    Percent-encode text for URLs.

    The `safe` parameter mirrors urllib.parse.quote, allowing callers to leave certain
    characters unencoded.
    """
    return urllib.parse.quote(data, safe=safe)


def url_decode(encoded: str) -> str:
    """Decode percent-encoded URL text."""
    return urllib.parse.unquote(encoded)


def html_entity_encode(data: str) -> str:
    """Encode HTML entities."""
    return html.escape(data)


def html_entity_decode(data: str) -> str:
    """Decode HTML entities."""
    return html.unescape(data)


def unicode_escape_encode(data: str) -> str:
    """Encode string using \\uXXXX escapes."""
    return codecs.encode(data, "unicode_escape").decode("ascii")


def unicode_escape_decode(data: str) -> str:
    """Decode \\uXXXX style escapes."""
    return codecs.decode(data, "unicode_escape")
