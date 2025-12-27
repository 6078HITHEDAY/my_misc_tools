from collections import defaultdict
from typing import Dict, List

# International Morse Code for letters, digits, and a few common punctuation marks.
MORSE_CODE: Dict[str, str] = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "!": "-.-.--",
    "/": "-..-.",
    "@": ".--.-.",
    "-": "-....-",
    "(": "-.--.",
    ")": "-.--.-",
}

MORSE_REVERSE: Dict[str, str] = {code: letter for letter, code in MORSE_CODE.items()}


def caesar_shift(text: str, shift: int) -> str:
    """
    Shift alphabetic characters by `shift` positions (wraps through A-Z/a-z).
    Non-alphabetic characters are left unchanged.
    """
    result: List[str] = []
    normalized_shift = shift % 26

    for char in text:
        if "a" <= char <= "z":
            offset = ord("a")
            shifted = chr(offset + (ord(char) - offset + normalized_shift) % 26)
            result.append(shifted)
        elif "A" <= char <= "Z":
            offset = ord("A")
            shifted = chr(offset + (ord(char) - offset + normalized_shift) % 26)
            result.append(shifted)
        else:
            result.append(char)
    return "".join(result)


def rot13(text: str) -> str:
    """ROT13 convenience wrapper around the Caesar shift."""
    return caesar_shift(text, 13)


def rot5(text: str) -> str:
    """ROT5 for digits."""
    out: List[str] = []
    for ch in text:
        if ch.isdigit():
            out.append(str((int(ch) + 5) % 10))
        else:
            out.append(ch)
    return "".join(out)


def rot18(text: str) -> str:
    """ROT13 for letters + ROT5 for digits."""
    interim = rot13(text)
    return rot5(interim)


def rot47(text: str) -> str:
    """ROT47 over printable ASCII (33-126)."""
    out = []
    for ch in text:
        code = ord(ch)
        if 33 <= code <= 126:
            out.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def rot8000(text: str) -> str:
    """Rotate Unicode code points by 0x8000 (mod 0x10000)."""
    out = []
    for ch in text:
        out.append(chr((ord(ch) + 0x8000) % 0x10000))
    return "".join(out)


def rot_special(text: str) -> str:
    """Alias to ROT47 for compatibility."""
    return rot47(text)


def atbash(text: str) -> str:
    """
    Atbash substitution (A<->Z, a<->z).
    """
    result: List[str] = []
    for ch in text:
        if "A" <= ch <= "Z":
            result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        elif "a" <= ch <= "z":
            result.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            result.append(ch)
    return "".join(result)


def vigenere_encrypt(text: str, key: str) -> str:
    """
    Encrypt text using Vigenere cipher (letters only affected).
    """
    if not key:
        raise ValueError("Key must not be empty.")
    result: List[str] = []
    key_shifts = [ord(k.lower()) - ord("a") for k in key if k.isalpha()]
    if not key_shifts:
        raise ValueError("Key must contain alphabetic characters.")
    idx = 0
    for ch in text:
        if ch.isalpha():
            shift = key_shifts[idx % len(key_shifts)]
            idx += 1
            result.append(caesar_shift(ch, shift))
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt Vigenere cipher."""
    if not key:
        raise ValueError("Key must not be empty.")
    key_shifts = [ord(k.lower()) - ord("a") for k in key if k.isalpha()]
    if not key_shifts:
        raise ValueError("Key must contain alphabetic characters.")
    idx = 0
    result: List[str] = []
    for ch in text:
        if ch.isalpha():
            shift = key_shifts[idx % len(key_shifts)]
            idx += 1
            result.append(caesar_shift(ch, -shift))
        else:
            result.append(ch)
    return "".join(result)


def morse_encode(text: str) -> str:
    """
    Encode a message into Morse code.

    Letters inside a word are separated with spaces; words are separated with "/".
    """
    words: List[str] = []
    for word in text.split(" "):
        letters: List[str] = []
        for char in word:
            upper_char = char.upper()
            if upper_char not in MORSE_CODE:
                raise ValueError(f"Character '{char}' cannot be encoded in Morse code.")
            letters.append(MORSE_CODE[upper_char])
        words.append(" ".join(letters))
    return " / ".join(words)


def morse_decode(code: str) -> str:
    """
    Decode a Morse code message back into text.

    Words are expected to be separated by "/" characters; letters by spaces.
    """
    decoded_words: List[str] = []
    for word in code.strip().split("/"):
        letters: List[str] = []
        stripped_word = word.strip()
        if not stripped_word:
            continue
        for symbol in stripped_word.split():
            if symbol not in MORSE_REVERSE:
                raise ValueError(f"Symbol '{symbol}' is not valid Morse code.")
            letters.append(MORSE_REVERSE[symbol])
        decoded_words.append("".join(letters))
    return " ".join(decoded_words)


def rail_fence_encrypt(text: str, rails: int) -> str:
    """
    Encrypt text using a Rail Fence cipher with the specified number of rails.
    """
    if rails < 2 or len(text) <= 1:
        return text

    fence = ["" for _ in range(rails)]
    rail_index = 0
    direction = 1  # 1 for moving down, -1 for moving up

    for char in text:
        fence[rail_index] += char
        rail_index += direction
        if rail_index == 0 or rail_index == rails - 1:
            direction *= -1

    return "".join(fence)


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    """
    Decrypt a Rail Fence cipher with the specified number of rails.
    """
    if rails < 2 or len(ciphertext) <= 1:
        return ciphertext

    # Determine which rail each character belongs to based on zigzag traversal.
    pattern: List[int] = []
    rail_index = 0
    direction = 1
    for _ in ciphertext:
        pattern.append(rail_index)
        rail_index += direction
        if rail_index == 0 or rail_index == rails - 1:
            direction *= -1

    # Count how many characters go to each rail.
    counts: Dict[int, int] = defaultdict(int)
    for rail in pattern:
        counts[rail] += 1

    # Split ciphertext into slices per rail.
    rail_slices: List[List[str]] = []
    start = 0
    for rail in range(rails):
        end = start + counts[rail]
        rail_slices.append(list(ciphertext[start:end]))
        start = end

    # Rebuild plaintext by consuming from each rail in pattern order.
    rail_positions = [0] * rails
    plaintext_chars: List[str] = []
    for rail in pattern:
        idx = rail_positions[rail]
        plaintext_chars.append(rail_slices[rail][idx])
        rail_positions[rail] += 1

    return "".join(plaintext_chars)
