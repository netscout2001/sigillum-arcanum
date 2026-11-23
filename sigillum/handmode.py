"""Hand-Modus v2: One-Time-Pad mit Fälschungsschutz – von Hand rechenbar.

Rechnen geschieht im Körper GF(32) (Polynom x^5 + x^2 + 1). Dafür gibt es zwei gedruckte Tafeln:
  * XOR-Tafel  (a ⊕ b)   – zum Ver- und Entschlüsseln und zum Aufsummieren
  * Mal-Tafel  (a ⊗ b)   – für den Prüfwert

Verschlüsseln:  c_i = p_i ⊕ v_i                                    (v = Verschlüsselungswert der Zeile i)
Prüfwerte:      t_j = m_j ⊕ (k_{j,1}⊗p_1) ⊕ (k_{j,2}⊗p_2) ⊕ …      (j = 1..4, k und m aus dem Blatt)

Die Prüfschlüssel k und Masken m sind geheim und einmalig (Wegman–Carter). Wer das Blatt nicht kennt,
kann eine Nachricht nur mit Wahrscheinlichkeit 1 : 32^4 = 1 : 1.048.576 unbemerkt verändern – auch mit
unbegrenzter Rechenleistung (KI, Quantencomputer). Die Vertraulichkeit ist beweisbar perfekt.

Klartext-Tabelle (32 Werte):
  Buchstaben-Modus: 0-25 = A-Z, 26 = Leerzeichen, 27 = '.', 28 = ',',
                    29 = Umschalten Ziffern/Buchstaben, 30 = Satzzeichen (nächster Wert 0-6), 31 = Füllzeichen
  Ziffern-Modus:    0-9 = Ziffern, 26/27/28/30/31 wie oben, 29 = zurück zu Buchstaben
  Satzzeichen:      0 ? | 1 ! | 2 : | 3 - | 4 ( | 5 ) | 6 "
Aufbau: [Blockzahl hoch, Blockzahl tief] + Text (aufgefüllt mit 31 auf ein Vielfaches von 20) + 4 Prüfwerte.
"""
import hmac
import secrets

from .core import h3
from .i18n import _

SPACE, DOT, COMMA, SHIFT, PUNCT, FILL = 26, 27, 28, 29, 30, 31
PUNCTS = '?!:-()"'
BLOCK = 10
PAD_TO = 20
TAGS = 4
POLY = 0b100101                       # x^5 + x^2 + 1
MAX_BLOCKS = 60
CODE_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
REPLACE = {"Ä": "AE", "Ö": "OE", "Ü": "UE", "ß": "SS", "ẞ": "SS", "„": '"', "“": '"', "”": '"',
           "–": "-", "—": "-", "\n": " ", "\t": " "}


class HandError(Exception):
    pass


# ---------------------------------------------------------------- GF(32)

def gf_mul(a: int, b: int) -> int:
    r = 0
    for _u in range(5):
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x20:
            a ^= POLY
    return r


# ---------------------------------------------------------------- Klartext-Tabelle

def normalize(text: str) -> str:
    out = []
    for ch in text:
        up = ch.upper()
        out.append(REPLACE.get(ch, REPLACE.get(up, up)))
    return "".join(out)


def text_to_values(text: str) -> list[int]:
    vals, digits = [], False
    for ch in normalize(text):
        if "A" <= ch <= "Z":
            if digits:
                vals.append(SHIFT)
                digits = False
            vals.append(ord(ch) - 65)
        elif ch in "0123456789":
            if not digits:
                vals.append(SHIFT)
                digits = True
            vals.append(int(ch))
        elif ch == " ":
            vals.append(SPACE)
        elif ch == ".":
            vals.append(DOT)
        elif ch == ",":
            vals.append(COMMA)
        elif ch in PUNCTS:
            vals += [PUNCT, PUNCTS.index(ch)]
        else:
            raise HandError(_("Zeichen nicht in der Hand-Tabelle: {0!r}").format(ch))
    return vals


def values_to_text(vals: list[int]) -> str:
    out, digits, i = [], False, 0
    while i < len(vals):
        v = vals[i]
        if v == SHIFT:
            digits = not digits
        elif v == SPACE:
            out.append(" ")
        elif v == DOT:
            out.append(".")
        elif v == COMMA:
            out.append(",")
        elif v == PUNCT:
            i += 1
            if i >= len(vals) or vals[i] >= len(PUNCTS):
                raise HandError(_("Ungültiges Satzzeichen."))
            out.append(PUNCTS[vals[i]])
        elif v == FILL:
            pass
        elif digits:
            if v > 9:
                raise HandError(_("Ungültiger Wert im Ziffern-Modus."))
            out.append(str(v))
        else:
            out.append(chr(65 + v))
        i += 1
    return "".join(out)


def frame(text: str) -> list[int]:
    """Klartext -> [Blockzahl hoch, tief] + Text + Auffüllung (Vielfaches von 20)."""
    body = text_to_values(text)
    body += [FILL] * ((-len(body)) % PAD_TO)
    if not body:
        body = [FILL] * PAD_TO
    blocks = len(body) // BLOCK
    if blocks > MAX_BLOCKS:
        raise HandError(_("Text zu lang: höchstens {0} Werte.").format(MAX_BLOCKS * BLOCK))
    return [blocks // 32, blocks % 32] + body


# ---------------------------------------------------------------- Zufallsblatt

class Sheet:
    """Ein Zufallsblatt: id, Masken m[4], und je Zeile i: v_i (Verschlüsselung) + k_{1..4,i} (Prüfschlüssel)."""

    def __init__(self, sid: str, masks: list, rows: list):
        if len(masks) != TAGS or any(len(r) != 1 + TAGS for r in rows):
            raise HandError(_("Blatt ungültig."))
        if any(not 0 <= x < 32 for x in masks) or any(not 0 <= x < 32 for r in rows for x in r):
            raise HandError(_("Blatt ungültig."))
        self.id, self.masks, self.rows = sid, masks, rows

    @classmethod
    def new(cls, blocks: int):
        if not 2 <= blocks <= MAX_BLOCKS:
            raise HandError(_("Blattgröße 2–{0} Blöcke.").format(MAX_BLOCKS))
        n = 2 + BLOCK * blocks
        sid = "-".join(secrets.token_hex(2).upper() for _u in range(4))       # 64 Bit (Befund L7)
        return cls(sid, [secrets.randbelow(32) for _u in range(TAGS)],
                   [[secrets.randbelow(32) for _u in range(1 + TAGS)] for _u in range(n)])

    def code(self) -> str:
        """Kompakte Abschrift für die Rechenhilfe (Befund R2-2):
        Blatt-Nr. (13 Zeichen) | Masken | je Zeile 5 Zeichen | Prüfsumme (10 Zeichen, 50 Bit) über alles davor."""
        flat = _sid_values(self.id) + self.masks + [x for r in self.rows for x in r]
        flat += _code_check(flat)
        s = "".join(CODE_ALPHA[x] for x in flat)
        return " ".join(s[i:i + 5] for i in range(0, len(s), 5))

    @classmethod
    def from_code(cls, sid: str, code: str):
        """Liest den Blattcode. Prüfsumme, Blattgröße und Blatt-Nr. müssen stimmen – sonst Ablehnung, damit nie ein
        falsches Blatt im Register landet und ein echtes dadurch zweimal benutzt werden kann."""
        vals = []
        for ch in code:                              # exakt Zeichen für Zeichen (Befund R3-3)
            if ch in " -\n\t\r":
                continue
            if ch not in _CODE_IDX:
                raise HandError(_("Ungültiges Zeichen im Blattcode: {0!r}").format(ch))
            vals.append(_CODE_IDX[ch])
        if len(vals) < SID_CHARS + CHECK_CHARS + TAGS + (1 + TAGS) * (2 + BLOCK * 2):
            raise HandError(_("Blattcode unvollständig."))
        body, check = vals[:-CHECK_CHARS], vals[-CHECK_CHARS:]
        if not hmac.compare_digest(bytes(_code_check(body)), bytes(check)):
            raise HandError(_("Blattcode fehlerhaft abgeschrieben (Prüfsumme stimmt nicht). Bitte Zeichen für "
                              "Zeichen mit der letzten Seite des Blatts vergleichen."))
        code_sid = _sid_from_values(body[:SID_CHARS])
        table = body[SID_CHARS:]
        n_rows, rest = divmod(len(table) - TAGS, 1 + TAGS)
        if rest or (n_rows - 2) % BLOCK or not 2 <= (n_rows - 2) // BLOCK <= MAX_BLOCKS:
            raise HandError(_("Blattcode hat keine gültige Blattgröße."))
        if not hmac.compare_digest(normalize_sid(sid).encode(), code_sid.encode()):
            raise HandError(_("Blatt-Nr. passt nicht zum Blattcode (der Code gehört zu Blatt {0}). Bitte die "
                              "Nummer oben auf dem Blatt prüfen.").format(code_sid))
        rows = [table[i:i + 1 + TAGS] for i in range(TAGS, len(table), 1 + TAGS)]
        return cls(code_sid, table[:TAGS], rows)


_CODE_IDX = {c: i for i, c in enumerate(CODE_ALPHA)} | {c.lower(): i for i, c in enumerate(CODE_ALPHA) if c.isalpha()}
SID_CHARS = 13                      # 64 Bit Blatt-Nr. in Base32 (65 Bit, oberstes Bit 0)
CHECK_CHARS = 10                    # 50 Bit Prüfsumme


def _sid_values(sid: str) -> list:
    n = int(normalize_sid(sid).replace("-", ""), 16)
    return [(n >> (5 * (SID_CHARS - 1 - i))) & 31 for i in range(SID_CHARS)]


def _sid_from_values(vals: list) -> str:
    n = 0
    for v in vals:
        n = (n << 5) | v
    if n >> 64:
        raise HandError(_("Blattcode fehlerhaft (Blatt-Nr. ungültig)."))
    h = f"{n:016X}"
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


def _code_check(vals: list) -> list:
    d = int.from_bytes(h3(b"SIGILLUM-SHEET", bytes(vals), 8), "big") >> 14
    return [(d >> (5 * (CHECK_CHARS - 1 - i))) & 31 for i in range(CHECK_CHARS)]


def message_digest(cipher: list) -> str:
    """Kennung einer Hand-Nachricht für das Blatt-Register (erkennt dieselbe Nachricht wieder, nicht geheim)."""
    return h3(b"SIGILLUM-HMSG", bytes(cipher), 16).hex()


def normalize_sid(sid: str) -> str:
    h = "".join(c.upper() for c in sid if c in "0123456789ABCDEFabcdef")
    if len(h) != 16:
        raise HandError(_("Blatt-Nr. muss 16 Zeichen haben (z. B. 3F2A-91C0-7D4E-B812)."))
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


# ---------------------------------------------------------------- Verschlüsseln / Entschlüsseln

def _tags(plain: list, sheet: Sheet) -> list:
    out = []
    for j in range(TAGS):
        t = sheet.masks[j]
        for i, p in enumerate(plain):
            t ^= gf_mul(sheet.rows[i][1 + j], p)
        out.append(t)
    return out


def encrypt(text: str, sheet: Sheet) -> list[int]:
    p = frame(text)
    if len(p) > len(sheet.rows):
        raise HandError(_("Zufallsblatt zu kurz: {0} Zeilen nötig, {1} vorhanden.").format(len(p), len(sheet.rows)))
    return [x ^ sheet.rows[i][0] for i, x in enumerate(p)] + _tags(p, sheet)


def decrypt(cipher: list[int], sheet: Sheet) -> str:
    n = len(cipher) - TAGS
    if n < 2 + PAD_TO or (n - 2) % PAD_TO:
        raise HandError(_("Länge passt nicht zum Hand-Format."))
    if n > len(sheet.rows):
        raise HandError(_("Zufallsblatt kürzer als die Nachricht."))
    if any(not 0 <= x < 32 for x in cipher):
        raise HandError(_("Ungültiger Wert."))
    p = [x ^ sheet.rows[i][0] for i, x in enumerate(cipher[:n])]
    ok = hmac.compare_digest(bytes(_tags(p, sheet)), bytes(cipher[n:]))
    if not ok or p[0] * 32 + p[1] != (n - 2) // BLOCK:
        raise HandError(_("PRÜFUNG FEHLGESCHLAGEN: Die Nachricht wurde verändert oder falsch abgeschrieben. Der "
                          "Inhalt wird nicht angezeigt. Abschrift und Blatt-Nr. prüfen."))
    return values_to_text(p[2:])
