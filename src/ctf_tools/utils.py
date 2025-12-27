from typing import Dict


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
