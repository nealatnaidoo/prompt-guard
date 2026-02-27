"""Shared Unicode confusable character mappings.

Maps visually similar characters (homoglyphs) to their ASCII equivalents.
Used by both the heuristic detector (for detection) and the content
sanitiser (for normalisation).
"""

from __future__ import annotations

# Cyrillic characters that are visually identical to Latin letters
CYRILLIC_CONFUSABLES: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X", "\u0430": "a",
    "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0455": "s", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h",
}

# Fullwidth ASCII variants (A-Z, a-z, 0-9)
FULLWIDTH_CONFUSABLES: dict[str, str] = {}
for _offset in range(26):
    FULLWIDTH_CONFUSABLES[chr(0xFF21 + _offset)] = chr(0x41 + _offset)  # A-Z
    FULLWIDTH_CONFUSABLES[chr(0xFF41 + _offset)] = chr(0x61 + _offset)  # a-z
for _offset in range(10):
    FULLWIDTH_CONFUSABLES[chr(0xFF10 + _offset)] = chr(0x30 + _offset)  # 0-9

# Complete confusable map: Cyrillic + fullwidth
CONFUSABLE_MAP: dict[str, str] = {**CYRILLIC_CONFUSABLES, **FULLWIDTH_CONFUSABLES}
