import subprocess
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Optional

PREFERRED_ENCODINGS: List[str] = [
    "utf-8",
    "gb18030",
    "big5",
    "shift_jis",
    "cp1252",
    "latin-1",
]


def reverse_string(text: str) -> str:
    """Return the string reversed."""
    return text[::-1]


def to_upper(text: str) -> str:
    """Convert all characters to uppercase."""
    return text.upper()


def to_lower(text: str) -> str:
    """Convert all characters to lowercase."""
    return text.lower()


def swap_case(text: str) -> str:
    """Swap the case of each character."""
    return text.swapcase()


def simple_replace(text: str, replacements: Dict[str, str]) -> str:
    """
    Replace characters in a string based on a mapping.

    The mapping keys and values are treated as literal strings (commonly single
    characters). If a character is not present in the mapping, it is left as-is.
    """
    return "".join(replacements.get(char, char) for char in text)


def decode_bytes_best_effort(data: bytes, preferred_encoding: Optional[str] = None, encodings: Optional[Iterable[str]] = None) -> str:
    """
    Decode bytes with a set of common encodings, falling back to replacement on failure.

    - If preferred_encoding is provided, try it first.
    - Then try the provided list (or the default preferred list).
    - If all fail, decode with the first candidate using replacement to avoid crashes.
    """
    candidates: List[str] = []
    if preferred_encoding:
        candidates.append(preferred_encoding)
    if encodings:
        candidates.extend(list(encodings))
    else:
        candidates.extend(PREFERRED_ENCODINGS)
    # de-duplicate while preserving order
    seen = set()
    ordered = []
    for enc in candidates:
        if enc and enc.lower() not in seen:
            ordered.append(enc)
            seen.add(enc.lower())
    if not ordered:
        ordered = ["utf-8", "latin-1"]

    for enc in ordered:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    # last resort: replacement to avoid raising
    return data.decode(ordered[0], errors="replace")


def detect_encoding_via_file(path: Path) -> Optional[str]:
    """
    Use the `file` command to guess encoding; returns lower-case encoding name or None.
    """
    if not shutil.which("file"):
        return None
    try:
        proc = subprocess.run(
            ["file", "-b", "--mime-encoding", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            enc = proc.stdout.strip().lower()
            return enc or None
    except Exception:
        return None
    return None
