"""Hand-Modus v2: GF(32), One-Time-Pad, Fälschungsschutz."""
import itertools
import random

import pytest

from sigillum import handmode as h


def test_gf32_is_a_field():
    elems = range(32)
    for a, b in itertools.product(elems, elems):
        assert h.gf_mul(a, b) == h.gf_mul(b, a)
        if a and b:
            assert h.gf_mul(a, b) != 0                     # keine Nullteiler
    for a in range(1, 32):
        assert sorted(h.gf_mul(a, b) for b in elems) == list(elems)      # jede Zeile ist eine Permutation
    for a, b, c in itertools.product(range(0, 32, 3), range(1, 32, 5), range(2, 32, 7)):
        assert h.gf_mul(a, b ^ c) == h.gf_mul(a, b) ^ h.gf_mul(a, c)      # Distributivgesetz
        assert h.gf_mul(h.gf_mul(a, b), c) == h.gf_mul(a, h.gf_mul(b, c))


def test_table_roundtrip():
    t = 'Treffen um 14:30, Tor 3! (wirklich?) "ja" - äöüß.'
    assert h.values_to_text(h.text_to_values(t)) == h.normalize(t)


def test_roundtrip_and_length_hiding():
    s = h.Sheet.new(10)
    c1 = h.encrypt("Treffen um 14:30", s)
    assert h.decrypt(c1, s) == "TREFFEN UM 14:30"
    assert len(c1) == len(h.encrypt("A", h.Sheet.new(10))) == 2 + 20 + 4


def test_code_roundtrip():
    for blocks in (2, 3, 10, h.MAX_BLOCKS):
        s = h.Sheet.new(blocks)
        s2 = h.Sheet.from_code(s.id.lower().replace("-", ""), s.code().lower())
        assert s2.id == s.id and s2.masks == s.masks and s2.rows == s.rows
    with pytest.raises(h.HandError):
        h.Sheet.from_code(s.id, s.code()[:-3])
    with pytest.raises(h.HandError):
        h.normalize_sid("1234")


def test_r2_2_sheet_id_bound_to_code():
    """R2-2: falsche Blatt-Nr. wird abgelehnt – kein falscher Eintrag im Register."""
    s = h.Sheet.new(4)
    other = h.Sheet.new(4).id
    with pytest.raises(h.HandError, match="passt nicht"):
        h.Sheet.from_code(other, s.code())
    wrong = s.id[:-1] + ("0" if s.id[-1] != "0" else "1")
    with pytest.raises(h.HandError, match="passt nicht"):
        h.Sheet.from_code(wrong, s.code())


def test_r2_2_every_typo_in_code_detected():
    """Jedes einzelne falsch abgeschriebene Zeichen und jedes Vertauschen zweier Nachbarn wird erkannt."""
    s = h.Sheet.new(2)
    raw = s.code().replace(" ", "")
    for i in range(len(raw)):
        for ch in h.CODE_ALPHA:
            if ch != raw[i]:
                with pytest.raises(h.HandError):
                    h.Sheet.from_code(s.id, raw[:i] + ch + raw[i + 1:])
    for i in range(len(raw) - 1):
        if raw[i] != raw[i + 1]:
            with pytest.raises(h.HandError):
                h.Sheet.from_code(s.id, raw[:i] + raw[i + 1] + raw[i] + raw[i + 2:])


def test_r2_2_truncated_or_extended_code_rejected():
    s = h.Sheet.new(4)
    raw = s.code().replace(" ", "")
    for bad in (raw[:-5], raw[:-25], raw + "AAAAA", raw[:30] + raw[35:], raw[:30] + "AAAAA" + raw[30:]):
        with pytest.raises(h.HandError):
            h.Sheet.from_code(s.id, bad)


def test_r2_2_forged_code_with_valid_checksum_but_bad_size():
    """Auch mit korrekt neu berechneter Prüfsumme: nur gültige Blattgrößen."""
    s = h.Sheet.new(4)
    body = h._sid_values(s.id) + s.masks + [x for r in s.rows[:-5] for x in r]
    code = "".join(h.CODE_ALPHA[x] for x in body + h._code_check(body))
    with pytest.raises(h.HandError, match="Blattgröße"):
        h.Sheet.from_code(s.id, code)


def test_message_digest_distinguishes():
    s = h.Sheet.new(2)
    c = h.encrypt("A", s)
    assert h.message_digest(c) == h.message_digest(list(c)) != h.message_digest(h.encrypt("B", s))


def test_every_single_change_detected():
    s = h.Sheet.new(4)
    c = h.encrypt("Treffen um 14:30", s)
    for i in range(len(c)):
        for d in range(1, 32):
            x = list(c)
            x[i] ^= d
            with pytest.raises(h.HandError):
                h.decrypt(x, s)


def test_targeted_attack_from_audit_fails():
    """Der Angriff aus Befund H2 (14:30 -> 16:30) gelingt nicht mehr."""
    s = h.Sheet.new(4)
    c = h.encrypt("TREFFEN UM 14:30", s)
    p = h.frame("TREFFEN UM 14:30")
    pos = p.index(4, 2)                                    # die Ziffer 4
    x = list(c)
    x[pos] ^= 4 ^ 6
    with pytest.raises(h.HandError):
        h.decrypt(x, s)


def test_forgery_rate_statistics():
    """Zufällige Fälschungsversuche mit angepassten Prüfwerten: erwartet ~1 : 1.048.576."""
    rng = random.Random(7)
    s = h.Sheet.new(2)
    c = h.encrypt("GEHEIM", s)
    n = len(c) - h.TAGS
    hits = 0
    for _ in range(20000):
        x = list(c)
        x[rng.randrange(n)] ^= rng.randrange(1, 32)
        for j in range(h.TAGS):
            x[n + j] = rng.randrange(32)
        try:
            h.decrypt(x, s)
            hits += 1
        except h.HandError:
            pass
    assert hits <= 1


def test_truncation_and_extension_rejected():
    s = h.Sheet.new(6)
    c = h.encrypt("X" * 30, s)                             # 2 Blöcke à 20
    n = len(c) - h.TAGS
    with pytest.raises(h.HandError):
        h.decrypt(c[:n - 20] + c[n:], s)                    # Block weggelassen, alte Prüfwerte
    with pytest.raises(h.HandError):
        h.decrypt(c[:n] + [0] * 20 + c[n:], s)               # Block angehängt
    for d in range(1, 32):                                  # Blockzahl verändert + Länge angepasst
        x = c[:n - 20] + c[n:]
        x[1] ^= d
        with pytest.raises(h.HandError):
            h.decrypt(x, s)


def test_sheet_too_short_and_bad_values():
    s = h.Sheet.new(2)
    with pytest.raises(h.HandError):
        h.encrypt("X" * 50, s)
    c = h.encrypt("ok", s)
    c[0] = 32
    with pytest.raises(h.HandError):
        h.decrypt(c, s)


def test_sheet_ids_unique_64bit():
    ids = {h.Sheet.new(2).id for _ in range(2000)}
    assert len(ids) == 2000 and all(len(i) == 19 for i in ids)


def test_unknown_char():
    with pytest.raises(h.HandError):
        h.text_to_values("€")


def test_r3_3_sheet_code_exact_characters():
    s = h.Sheet.new(2)
    raw = s.code().replace(" ", "")
    i = raw.index("S") if "S" in raw else None
    if i is not None and i + 1 < len(raw) and raw[i + 1] == "T":
        bad = raw[:i] + "ﬆ" + raw[i + 2:]
        with pytest.raises(h.HandError, match="Ungültiges Zeichen"):
            h.Sheet.from_code(s.id, bad)
    with pytest.raises(h.HandError, match="Ungültiges Zeichen"):
        h.Sheet.from_code(s.id, raw[:5] + "ﬆ" + raw[5:])
    assert h.Sheet.from_code(s.id.lower(), raw.lower()).rows == s.rows
