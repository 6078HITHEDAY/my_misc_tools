import base64
import zlib
import gzip
import string
from typing import Dict, Tuple, Callable

BASE91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
BASE92_ALPHABET = (
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}"
)
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base45_encode(data: bytes) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    res = []
    i = 0
    while i < len(data):
        if i + 1 < len(data):
            x = (data[i] << 8) + data[i + 1]
            res.append(alphabet[x % 45])
            res.append(alphabet[(x // 45) % 45])
            res.append(alphabet[x // (45 * 45)])
            i += 2
        else:
            x = data[i]
            res.append(alphabet[x % 45])
            res.append(alphabet[x // 45])
            i += 1
    return "".join(res)


def base45_decode(text: str) -> bytes:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    inv = {c: i for i, c in enumerate(alphabet)}
    res = bytearray()
    i = 0
    while i < len(text):
        if i + 2 < len(text):
            c = inv[text[i]] + inv[text[i + 1]] * 45 + inv[text[i + 2]] * 45 * 45
            res.append(c // 256)
            res.append(c % 256)
            i += 3
        else:
            c = inv[text[i]] + inv[text[i + 1]] * 45
            res.append(c)
            i += 2
    return bytes(res)


def base62_encode(data: bytes, alphabet: str = BASE62_ALPHABET) -> str:
    num = int.from_bytes(data, "big")
    if num == 0:
        return alphabet[0]
    out = ""
    while num > 0:
        num, rem = divmod(num, 62)
        out = alphabet[rem] + out
    # leading zeros
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return alphabet[0] * pad + out


def base62_decode(text: str, alphabet: str = BASE62_ALPHABET) -> bytes:
    num = 0
    for ch in text:
        num = num * 62 + alphabet.index(ch)
    length = max(1, (num.bit_length() + 7) // 8)
    out = num.to_bytes(length, "big")
    pad = len(text) - len(text.lstrip(alphabet[0]))
    return b"\x00" * pad + out.lstrip(b"\x00")


def base58_encode(data: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return alphabet[0] * pad + out or alphabet[0]


def base58_decode(encoded: str, alphabet: str = BASE58_ALPHABET) -> bytes:
    num = 0
    for ch in encoded:
        num = num * 58 + alphabet.index(ch)
    length = max(1, (num.bit_length() + 7) // 8)
    out = num.to_bytes(length, "big")
    pad = len(encoded) - len(encoded.lstrip(alphabet[0]))
    return b"\x00" * pad + out.lstrip(b"\x00")


def base36_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    if num == 0:
        return "0"
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = ""
    while num:
        num, rem = divmod(num, 36)
        out = digits[rem] + out
    return out


def base36_decode(text: str) -> bytes:
    num = int(text, 36)
    length = max(1, (num.bit_length() + 7) // 8)
    return num.to_bytes(length, "big")


def base91_encode(data: bytes) -> str:
    b = 0
    n = 0
    out = ""
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out += BASE91_ALPHABET[v % 91]
            out += BASE91_ALPHABET[v // 91]
    if n:
        out += BASE91_ALPHABET[b % 91]
        if n > 7 or b > 90:
            out += BASE91_ALPHABET[b // 91]
    return out


def base91_decode(text: str) -> bytes:
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for ch in text:
        c = BASE91_ALPHABET.index(ch)
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return bytes(out)


def base92_encode(data: bytes) -> str:
    b = 0
    n = 0
    out = ""
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out += BASE92_ALPHABET[v % 92]
            out += BASE92_ALPHABET[v // 92]
    if n:
        out += BASE92_ALPHABET[b % 92]
        if n > 7 or b > 91:
            out += BASE92_ALPHABET[b // 92]
    return out


def base92_decode(text: str) -> bytes:
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for ch in text:
        c = BASE92_ALPHABET.index(ch)
        if v < 0:
            v = c
        else:
            v += c * 92
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n >= 8:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return bytes(out)


def base64_to_hex(text: str) -> str:
    return base64.b64decode(text).hex()


def base64_decompress(text: str) -> str:
    raw = base64.b64decode(text)
    try:
        return zlib.decompress(raw).decode("latin-1")
    except Exception:
        return gzip.decompress(raw).decode("latin-1")


def base100_encode(data: bytes) -> str:
    return " ".join(f"{b:02d}" for b in data)


def base100_decode(text: str) -> bytes:
    parts = [p for p in text.replace(",", " ").split() if p]
    return bytes(int(p) for p in parts)


BaseCodec = Tuple[Callable[[bytes], str], Callable[[str], bytes]]


def registry() -> Dict[str, BaseCodec]:
    return {
        "base16": (lambda b: b.hex(), lambda s: bytes.fromhex(s)),
        "base32": (lambda b: base64.b32encode(b).decode("ascii"), lambda s: base64.b32decode(s)),
        "base36": (lambda b: base36_encode(b), lambda s: base36_decode(s)),
        "base45": (lambda b: base45_encode(b), base45_decode),
        "base58": (lambda b: base58_encode(b), lambda s: base58_decode(s)),
        "base62": (lambda b: base62_encode(b), lambda s: base62_decode(s)),
        "base64": (lambda b: base64.b64encode(b).decode("ascii"), lambda s: base64.b64decode(s)),
        "base64url": (lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("="), lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))),
        "ascii85": (lambda b: base64.a85encode(b).decode("ascii"), lambda s: base64.a85decode(s)),
        "b85": (lambda b: base64.b85encode(b).decode("ascii"), lambda s: base64.b85decode(s)),
        "base91": (lambda b: base91_encode(b), lambda s: base91_decode(s)),
        "base92": (lambda b: base92_encode(b), lambda s: base92_decode(s)),
        "base100": (lambda b: base100_encode(b), lambda s: base100_decode(s)),
    }
