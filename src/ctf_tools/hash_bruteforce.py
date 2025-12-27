import hashlib
from typing import Iterable, Optional

from .modern_crypto import HashAlgorithm

WEAK_PASSWORDS = [
    "123456",
    "password",
    "123456789",
    "12345678",
    "111111",
    "abc123",
    "qwerty",
    "letmein",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "football",
]


def _hash(text: str, algo: HashAlgorithm) -> str:
    h = getattr(hashlib, algo)()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def brute_force_hash(
    target_hash: str,
    algo: HashAlgorithm = "md5",
    dictionary: Optional[Iterable[str]] = None,
    use_rules: bool = True,
) -> Optional[str]:
    """
    Attempt to find a plaintext matching the given hash using a weak dictionary
    plus lightweight mangling rules.
    """
    words = dictionary if dictionary is not None else WEAK_PASSWORDS
    candidates = []
    for word in words:
        word = word.strip()
        if not word:
            continue
        candidates.append(word)
        if use_rules:
            candidates.extend(
                [
                    word + "123",
                    word + "1",
                    word.capitalize(),
                    word.capitalize() + "123",
                    word.replace("a", "@").replace("o", "0").replace("e", "3"),
                ]
            )
    for cand in candidates:
        if _hash(cand, algo) == target_hash.lower():
            return cand
    return None
