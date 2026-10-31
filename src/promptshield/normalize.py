"""Text normalization that defeats common obfuscation tricks.

Attackers hide instructions with zero-width characters, Unicode look-alikes,
full-width forms, odd spacing and leetspeak. Detectors run their patterns on
the normalized form so that ``ｉｇｎｏｒｅ`` and ``ign<U+200B>ore`` match ``ignore``.
"""

from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = frozenset(map(chr, (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD)))
BIDI_CONTROLS = frozenset(map(chr, (*range(0x202A, 0x202F), *range(0x2066, 0x206A))))
TAG_START, TAG_END = 0xE0000, 0xE007F

# Cyrillic and Greek letters that render like Latin ones.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "ո": "n",
        "ν": "v",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "Ζ": "Z",
        "ο": "o",
    }
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LEET_WORD = re.compile(r"\b(?=\w*[a-z])[\w@$]*[013457@$][\w@$]*\b")


def is_tag_char(ch: str) -> bool:
    return TAG_START <= ord(ch) <= TAG_END


def is_invisible(ch: str) -> bool:
    return ch in ZERO_WIDTH or ch in BIDI_CONTROLS or is_tag_char(ch)


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not is_invisible(ch))


def fold_leet(text: str) -> str:
    """Rewrite leetspeak inside words that also contain letters (``1gn0re`` -> ``ignore``)."""
    return _LEET_WORD.sub(lambda m: m.group(0).translate(_LEET), text)


def normalize(text: str) -> str:
    """Return a lower-cased, de-obfuscated, single-spaced copy of ``text``."""
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    text = text.translate(_HOMOGLYPHS)
    text = text.casefold()
    text = fold_leet(text)
    return re.sub(r"\s+", " ", text).strip()
