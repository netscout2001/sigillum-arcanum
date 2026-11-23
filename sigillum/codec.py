"""Darstellung: Bytes <-> 5-Bit-Werte <-> Glyphen (mit zufälliger Form) bzw. lateinische Umschrift.

Die Darstellung ist rein kosmetisch und öffentlich (Kerckhoffs). Sicherheit kommt allein aus der Kryptografie.
"""
import secrets

PUA_BASE = 0xE000          # Glyph = U+E000 + 32*form + wert
FORMS = 4
LATIN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"   # RFC-4648-Base32-Alphabet
_LATIN_IDX = {c: i for i, c in enumerate(LATIN)} | {c.lower(): i for i, c in enumerate(LATIN) if c.isalpha()}
LINE = 40


def bytes_to_values(data: bytes) -> list[int]:
    bits = 0
    nbits = 0
    out = []
    for byte in data:
        bits = (bits << 8) | byte
        nbits += 8
        while nbits >= 5:
            nbits -= 5
            out.append((bits >> nbits) & 31)
    if nbits:
        out.append((bits << (5 - nbits)) & 31)
    return out


def values_to_bytes(values: list[int]) -> bytes:
    bits = 0
    nbits = 0
    out = bytearray()
    for v in values:
        if not 0 <= v < 32:
            raise ValueError("Ungültiger Wert")
        bits = (bits << 5) | v
        nbits += 5
        if nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    return bytes(out)


def value_to_glyph(v: int) -> str:
    return chr(PUA_BASE + 32 * secrets.randbelow(FORMS) + v)


def values_to_glyphs(values: list[int], line: int = LINE) -> str:
    chars = [value_to_glyph(v) for v in values]
    return "\n".join("".join(chars[i:i + line]) for i in range(0, len(chars), line))


def values_to_latin(values: list[int], group: int = 5, line: int = 8) -> str:
    s = "".join(LATIN[v] for v in values)
    groups = [s[i:i + group] for i in range(0, len(s), group)]
    return "\n".join(" ".join(groups[i:i + line]) for i in range(0, len(groups), line))


MAX_CHARS = 4 * 1024 * 1024


def text_to_values(text: str) -> list[int]:
    """Erkennt Glyphen und lateinische Umschrift; Leerraum wird ignoriert."""
    if len(text) > MAX_CHARS:
        raise ValueError("Eingabe zu groß.")
    out = []
    for ch in text:
        if ch.isspace():
            continue
        cp = ord(ch)
        if PUA_BASE <= cp < PUA_BASE + 32 * FORMS:
            out.append((cp - PUA_BASE) % 32)
        elif ch in _LATIN_IDX:                       # exakt Zeichen für Zeichen (Befund R3-3)
            out.append(_LATIN_IDX[ch])
        else:
            raise ValueError(f"Unbekanntes Zeichen im Geheimtext: {ch!r}")
    return out


def encode(data: bytes, latin: bool = False) -> str:
    vals = bytes_to_values(data)
    return values_to_latin(vals) if latin else values_to_glyphs(vals)


def decode(text: str) -> bytes:
    return values_to_bytes(text_to_values(text))
