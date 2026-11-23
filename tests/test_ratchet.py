"""Tests für Identitätsdatei, Kontaktbuch und Schlüsselwechsel (Format v2)."""
import json
import random
import time

import pytest

from sigillum import core, ratchet
from sigillum.core import SigillumError

KF = core.new_keyfile()
PWA = "abacus zoom kettle velvet ample cactus"
PWB = "zebra yo-yo t-shirt drop-down felt-tip ample"


def mk(name, pw):
    return ratchet.Vault.create(name, pw, "481937", KF)


def link(*vaults):
    """Alle importieren und gegenseitig verifizieren (wie nach persönlichem Abgleich)."""
    for v in vaults:
        for w in vaults:
            if v is not w:
                c = w.identity.public()
                v.add_contact(c)
                v.verify_contact(c.fp(), c.fingerprint(), "persönlich")


def pair():
    a, b = mk("Anna", PWA), mk("Ben", PWB)
    link(a, b)
    return a, b, a.identity.public().fp(), b.identity.public().fp()


def keys_of(v, fp):
    return [k["id"] for k in v.state["contacts"].get(fp, {"my_keys": []})["my_keys"]]


def kid_used(r):
    return r["key"]


# ------------------------------------------------------------------ Grundablauf
def test_first_message_base_then_ratchet():
    a, b, fa, fb = pair()
    r = ratchet.decrypt(ratchet.encrypt("Hallo Ben", a, fb), b)
    assert r["text"] == "Hallo Ben" and r["key"] == "Basis-Schlüssel" and r["sender_name"] == "Anna"
    r = ratchet.decrypt(ratchet.encrypt("Hallo Anna", b, fa), a)
    assert r["text"] == "Hallo Anna" and r["key"] == "Wechselschlüssel Nr. 1"


def test_long_conversation_every_message_new_key():
    a, b, fa, fb = pair()
    seen = set()
    for i in range(25):
        ra = ratchet.decrypt(ratchet.encrypt(f"A{i}", a, fb), b)
        rb = ratchet.decrypt(ratchet.encrypt(f"B{i}", b, fa), a)
        assert ra["text"] == f"A{i}" and rb["text"] == f"B{i}"
        if i:
            assert ra["key"] != "Basis-Schlüssel"
        seen.add(("a", ra["key"]))
        seen.add(("b", rb["key"]))
        # R12-N1: je Nachricht POOL neue Schlüssel; der benutzte Einmal-Schlüssel ist sofort weg
        P = ratchet.POOL
        assert len(keys_of(a, fb)) == P - 1 and len(keys_of(b, fa)) == (P if i == 0 else 2 * P - 1)
    assert len(seen) == 50


def test_several_in_a_row():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hi", a, fb), b)
    msgs = [ratchet.encrypt(f"B{i}", b, fa) for i in range(5)]
    for i, m in enumerate(msgs):
        assert ratchet.decrypt(m, a)["text"] == f"B{i}"
    assert a.state["contacts"][fb]["their"]["seq"] == 5


# ------------------------------------------------------------------ Metadaten (M2) und Signaturen innen (M3)
def test_no_identifiers_in_ciphertext():
    a, b, fa, fb = pair()
    m = ratchet.encrypt("geheim", a, fb)
    pa, pb = a.identity.public(), b.identity.public()
    for needle in (pa.fp_raw(), pb.fp_raw(), pa.fp_raw()[:16], pb.fp_raw()[:16], pa.e_pub, pb.e_pub,
                   pb.kem_pk[-32:], pa.kem_pk[-32:]):
        assert needle not in m


def test_signature_not_checkable_from_outside():
    """Ohne Entschlüsselung keine Signatur: Die letzten Bytes sind Teil des AEAD-Chiffrats."""
    a, b, fa, fb = pair()
    m = ratchet.encrypt("geheim", a, fb)
    pub = a.identity.public()
    hits = 0
    for off in range(ratchet.HDR_LEN, len(m) - core.SIG_LEN, 97):
        try:
            core.verify_hybrid(pub, m[off:off + core.SIG_LEN], m[:off], ratchet.SIG_CONTEXT)
            hits += 1
        except SigillumError:
            pass
        try:
            core.ec_verify(pub.e_pub, m[off:off + core.EC_SIG], m[:off])
            hits += 1
        except Exception:
            pass
    assert hits == 0


def test_no_surreptitious_forwarding():
    """Ben kann Annas signierte Nachricht nicht an Carl weiterreichen, als wäre sie an Carl gerichtet."""
    a, b, fa, fb = pair()
    c = mk("Carl", PWA)
    link(a, b, c)
    m = ratchet.encrypt("Nur für Ben", a, fb)
    # Ben entschlüsselt, packt den inneren Teil unverändert neu für Carl
    header, ct = m[:ratchet.HDR_LEN], m[ratchet.HDR_LEN:]
    ss = b.identity.kem.decap(header[4:4 + core.HKEM_CT])
    key = ratchet._msg_key(ss, header, b.identity.public().fp_raw(), ratchet.BASE_ID)
    plain = core._aead_decrypt(ct, header, header[-core.NONCE_LEN:], key)
    ss2, kct = core.hkem_encap(c.identity.public().kem_pk)
    import secrets
    nonce = secrets.token_bytes(core.NONCE_LEN)
    h2 = core.MAGIC + bytes([core.VERSION, ratchet.MODE]) + kct + nonce
    forged = h2 + core._aead_encrypt(plain, h2, nonce,
                                     ratchet._msg_key(ss2, h2, c.identity.public().fp_raw(), ratchet.BASE_ID))
    with pytest.raises(SigillumError, match="Signatur"):
        ratchet.decrypt(forged, c)


# ------------------------------------------------------------------ Vorwärts-Sicherheit
def test_old_keys_deleted_immediately():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)
    old = ratchet.encrypt("an K1", b, fa)
    assert ratchet.decrypt(old, a)["text"] == "an K1"
    ratchet.decrypt(ratchet.encrypt("2", a, fb), b)
    # alter Vorrat (POOL-1 übrig) und der benutzte Einmal-Schlüssel des neuen Vorrats (R12-N1)
    assert ratchet.decrypt(ratchet.encrypt("an K2", b, fa), a)["deleted"] == ratchet.POOL
    with pytest.raises(SigillumError, match="schon geöffnet"):          # R12-N1: Einmal-Schlüssel gelöscht
        ratchet.decrypt(old, a)


def test_deleted_key_gone_from_file():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)
    seed1 = a.state["contacts"][fb]["my_keys"][0]["seed"]
    ratchet.decrypt(ratchet.encrypt("x", b, fa), a)
    ratchet.decrypt(ratchet.encrypt("2", a, fb), b)
    ratchet.decrypt(ratchet.encrypt("y", b, fa), a)
    raw = json.dumps(ratchet.Vault.open(a.to_blob(), PWA, "481937", KF).state)
    assert seed1 not in raw


# ------------------------------------------------------------------ Reihenfolge, Lücken, Stapel
def crossing(a, b, fa, fb):
    ratchet.decrypt(ratchet.encrypt("start", a, fb), b)
    m1 = ratchet.encrypt("eins", b, fa)
    ratchet.decrypt(ratchet.encrypt("dazwischen", a, fb), b)
    m2 = ratchet.encrypt("zwei", b, fa)
    return m1, m2


def test_gap_detected_before_deletion():
    a, b, fa, fb = pair()
    m1, m2 = crossing(a, b, fa, fb)
    before = json.dumps(a.state, sort_keys=True)
    o = ratchet.open_message(m2, a)
    assert o["result"]["gap"] == [1] and o["result"]["risk"]
    assert json.dumps(a.state, sort_keys=True) == before
    assert ratchet.decrypt(m1, a)["text"] == "eins"
    assert ratchet.decrypt(m2, a)["text"] == "zwei"


def test_batch_sorted():
    a, b, fa, fb = pair()
    m1, m2 = crossing(a, b, fa, fb)
    m3 = ratchet.encrypt("drei", b, fa)
    out = ratchet.process_batch([(0, m3), (1, m2), (2, m1)], a)
    assert [o["result"]["text"] for o in out] == ["eins", "zwei", "drei"]


def test_batch_two_senders_and_forgery():
    a, b, fa, fb = pair()
    c = mk("Carl", PWB)
    link(a, b, c)
    fc = c.identity.public().fp()
    mb, mc = ratchet.encrypt("von Ben", b, fa), ratchet.encrypt("von Carl", c, fa)
    fake = bytearray(ratchet.encrypt("fake", b, fa))
    fake[-10] ^= 1
    out = ratchet.process_batch([(0, mb), (1, bytes(fake)), (2, mc)], a)
    assert sorted(o["result"]["text"] for o in out if "result" in o) == ["von Ben", "von Carl"]
    assert [o["index"] for o in out if "error" in o] == [1]
    assert fc in a.state["contacts"] and fb in a.state["contacts"]


def test_lost_message_conversation_continues():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)
    ratchet.encrypt("verloren", a, fb)
    assert ratchet.decrypt(ratchet.encrypt("weiter", b, fa), a)["text"] == "weiter"
    ratchet.decrypt(ratchet.encrypt("3", a, fb), b)
    assert ratchet.decrypt(ratchet.encrypt("ok", b, fa), a)["text"] == "ok"


def test_simultaneous():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("i", a, fb), b)
    ratchet.decrypt(ratchet.encrypt("i", b, fa), a)
    ma, mb = ratchet.encrypt("A", a, fb), ratchet.encrypt("B", b, fa)
    assert ratchet.decrypt(ma, b)["text"] == "A" and ratchet.decrypt(mb, a)["text"] == "B"


# ------------------------------------------------------------------ Angriffe
def test_tampering_rejected_state_unchanged():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)
    m = ratchet.encrypt("geheim", b, fa)
    before = json.dumps(a.state, sort_keys=True)
    rng = random.Random(1)
    for pos in [2, 3, 10, 500, 1200, ratchet.HDR_LEN + 5, len(m) - 5] + [rng.randrange(len(m)) for _ in range(40)]:
        t = bytearray(m)
        t[pos] ^= 1 << rng.randrange(8)
        with pytest.raises(SigillumError):
            ratchet.decrypt(bytes(t), a)
        assert json.dumps(a.state, sort_keys=True) == before
    for t in (m[:-1], m + b"\x00", m[:100]):
        with pytest.raises(SigillumError):
            ratchet.decrypt(t, a)
    assert ratchet.decrypt(m, a)["text"] == "geheim"


def test_forged_sender_same_name():
    a, b, fa, fb = pair()
    mallory = mk("Anna", PWA)
    link(mallory, b)                                  # Ben hat Mallory NICHT verifiziert? -> hier doch, s. u.
    b.remove_contact(mallory.identity.public().fp())
    fake = ratchet.encrypt("Ich bin Anna", mallory, fb)
    with pytest.raises(SigillumError, match="unbekannt"):
        ratchet.decrypt(fake, b)


def test_unverified_contact_refused_both_ways():
    a, b = mk("Anna", PWA), mk("Ben", PWB)
    a.add_contact(b.identity.public())
    b.add_contact(a.identity.public())
    fb = b.identity.public().fp()
    with pytest.raises(SigillumError, match="nicht verifiziert"):
        ratchet.encrypt("x", a, fb)
    a.verify_contact(fb, b.identity.public().fingerprint(), "persönlich")
    m = ratchet.encrypt("x", a, fb)
    with pytest.raises(SigillumError, match="nicht verifiziert"):
        ratchet.decrypt(m, b)


def test_verification_requires_exact_fingerprint_and_method():
    a, b = mk("Anna", PWA), mk("Ben", PWB)
    c = b.identity.public()
    a.add_contact(c)
    fp = c.fingerprint()
    wrong = fp[:-1] + ("0" if fp[-1] != "0" else "1")
    for typed, method in ((wrong, "persönlich"), (fp[:-5], "persönlich"), (fp, "Telefon")):
        with pytest.raises(SigillumError):
            a.verify_contact(c.fp(), typed, method)
    assert not a.contact(c.fp())[1]
    a.verify_contact(c.fp(), fp.lower().replace(" ", ""), "Video mit Rückfrage")
    assert a.contact(c.fp())[1]


def test_key_of_other_contact_rejected():
    a, b, fa, fb = pair()
    c = mk("Carl", PWB)
    link(a, b, c)
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)               # Anna -> Ben: Annas Wechselschlüssel für Ben
    leaked = a.state["contacts"][fb]["their"]                      # (nur zur Konstruktion; Annas Seite)
    assert leaked is None
    ann_pk = b.state["contacts"][fa]["their"]                      # Ben kennt Annas Schlüssel K1(Ben)
    c.state["contacts"][fa] = {"my_keys": [], "next_seq": 1, "their": ann_pk, "sent": 0, "recv": 0, "last_ts": 0}
    m = ratchet.encrypt("Carl benutzt Bens Schlüssel", c, fa)     # Carl hat ihn irgendwie erhalten
    with pytest.raises(SigillumError, match="anderen Kontakt"):
        ratchet.decrypt(m, a)


def test_own_identity_cannot_be_contact():
    a = mk("Anna", PWA)
    with pytest.raises(SigillumError):
        a.add_contact(a.identity.public())


def test_same_name_warning():
    a, b = mk("Anna", PWA), mk("Ben", PWB)
    b2 = mk("ben", PWB)
    assert a.add_contact(b.identity.public()) == []
    assert [x.name for x in a.add_contact(b2.identity.public())] == ["Ben"]


# ------------------------------------------------------------------ Rücksetzen / Wiederholung
def test_partner_lost_state_reset():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)
    ratchet.decrypt(ratchet.encrypt("2", b, fa), a)
    ratchet.reset_contact(b, fa)
    r = ratchet.decrypt(ratchet.encrypt("neu", b, fa, now=time.time() + 60), a)
    assert r["partner_reset"] and a.state["contacts"][fb]["my_keys"] == []
    assert ratchet.decrypt(ratchet.encrypt("Antwort", a, fb), b)["text"] == "Antwort"
    assert ratchet.decrypt(ratchet.encrypt("weiter", b, fa), a)["text"] == "weiter"


def test_replayed_first_message():
    a, b, fa, fb = pair()
    first = ratchet.encrypt("erste", a, fb)
    ratchet.decrypt(first, b)
    ratchet.decrypt(ratchet.encrypt("x", b, fa), a)
    ratchet.decrypt(ratchet.encrypt("y", a, fb), b)
    snap = json.dumps(b.state["contacts"][fa]["their"])
    r = ratchet.decrypt(first, b)
    assert r["replay"] and not r["partner_reset"] and json.dumps(b.state["contacts"][fa]["their"]) == snap


def test_restored_old_backup_manual_reset():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("1", a, fb), b)
    backup = a.to_blob()
    for i in range(3):
        ratchet.decrypt(ratchet.encrypt(f"b{i}", b, fa), a)
        ratchet.decrypt(ratchet.encrypt(f"a{i}", a, fb), b)
    old = ratchet.Vault.open(backup, PWA, "481937", KF)
    with pytest.raises(SigillumError):
        ratchet.decrypt(ratchet.encrypt("neu", b, fa), old)
    ratchet.reset_contact(old, fb)
    assert ratchet.decrypt(ratchet.encrypt("Neustart", old, fb, now=time.time() + 60), b)["partner_reset"]
    assert ratchet.decrypt(ratchet.encrypt("wieder da", b, fa), old)["text"] == "wieder da"


# ------------------------------------------------------------------ Identitätsdatei
def test_vault_persistence_every_step():
    a, b, fa, fb = pair()
    blobs = {"a": a.to_blob(), "b": b.to_blob()}
    pws = {"a": PWA, "b": PWB}
    for i in range(4):
        for s, r, to in (("a", "b", fb), ("b", "a", fa)):
            vs = ratchet.Vault.open(blobs[s], pws[s], "481937", KF)
            m = ratchet.encrypt(f"{s}{i}", vs, to)
            blobs[s] = vs.to_blob()
            vr = ratchet.Vault.open(blobs[r], pws[r], "481937", KF)
            assert ratchet.decrypt(m, vr)["text"] == f"{s}{i}"
            blobs[r] = vr.to_blob()


def test_vault_book_and_sheets_encrypted():
    a, b, fa, fb = pair()
    a.mark_sheet("3F2A-91C0-7D4E-B812", "ab" * 16)
    blob = a.to_blob()
    for needle in (b"Ben", b"verified", b"3F2A", bytes.fromhex(fb)):
        assert needle not in blob
    v = ratchet.Vault.open(blob, PWA, "481937", KF)
    assert v.contact(fb)[1] and v.sheet_used("3F2A-91C0-7D4E-B812")
    assert v.sheet_message("3F2A-91C0-7D4E-B812") == "ab" * 16


def test_vault_rewrite_fresh_nonce_and_factors():
    a = mk("Anna", PWA)
    x, y = a.to_blob(), a.to_blob()
    assert x != y and x[:22] == y[:22]
    with pytest.raises(SigillumError):
        ratchet.Vault.open(x, PWA, "9999", KF)
    with pytest.raises(SigillumError):
        ratchet.Vault.open(x, PWA, "1234", core.new_keyfile())


def test_vault_clone_isolated():
    a, b, fa, fb = pair()
    w = a.clone()
    ratchet.encrypt("x", w, fb)
    assert fb not in a.state["contacts"] and fb in w.state["contacts"]


def test_open_key_cap():
    a, b, fa, fb = pair()
    old = ratchet.MAX_OPEN_KEYS
    ratchet.MAX_OPEN_KEYS = 2 * ratchet.POOL
    try:
        for _ in range(8):
            ratchet.encrypt("x", a, fb)
        assert [k["seq"] for k in a.state["contacts"][fb]["my_keys"]] == [7] * ratchet.POOL + [8] * ratchet.POOL
    finally:
        ratchet.MAX_OPEN_KEYS = old


def test_identity_factor_tags():
    a = mk("Anna", PWA)
    assert a.kf_digest == core.keyfile_digest(KF)
    assert a.same_passphrase(" ABACUS zoom kettle velvet ample cactus ") and not a.same_passphrase(PWB)


@pytest.mark.parametrize("twin", ["ben", "BEN", "\u0412\u0435\u043f", "Bén", "B3n"])
def test_lookalike_names_warned(twin):
    a, b = mk("Anna", PWA), mk("Ben", PWB)
    a.add_contact(b.identity.public())
    t = mk(twin, PWB)
    assert [x.name for x in a.add_contact(t.identity.public())] == ["Ben"]


def test_mixed_script_name_rejected():
    for name in ("B\u0435n", "B\u0435\u043f", "Αnna"):
        with pytest.raises(SigillumError, match="mischt"):
            mk(name, PWB)


# ------------------------------------------------------------------ zweite Prüfrunde
def test_r2_3_huge_sequence_jump_no_memory_blowup():
    """R2-3: riesiger Nummernsprung – Lücke nur als Anzahl, höchstens GAP_SHOW Nummern."""
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("x", a, fb), b)
    ratchet.decrypt(ratchet.encrypt("y", b, fa), a)
    ratchet.decrypt(ratchet.encrypt("y2", b, fa), a)
    a.state["contacts"][fb]["next_seq"] = 2 ** 62
    o = ratchet.open_message(ratchet.encrypt("z", a, fb), b)["result"]
    assert o["gap_count"] == 2 ** 62 - 2 and len(o["gap"]) == ratchet.GAP_SHOW and o["gap"][0] == 2
    good = ratchet.encrypt("gut", b, fa)
    assert ratchet.process_batch([(1, good)], a.clone())[0]["result"]["text"] == "gut"


def test_r2_3_sequence_limits():
    a, b, fa, fb = pair()
    ratchet.encrypt("w", a, fb)
    a.state["contacts"][fb]["next_seq"] = ratchet.MAX_SEQ
    with pytest.raises(SigillumError):
        ratchet.encrypt("z", a, fb)


def test_r2_4_invalid_ec_points_rejected():
    """R2-4 (v10): Ankündigung/Kontakt mit ungültigem EC-Punkt (Fernpunkt, komprimiert, nicht auf der Kurve,
    Koordinate >= p) wird abgelehnt."""
    pk = core.HybridKey.generate().pk
    pt = pk[-core.EC_PT:]
    p_field = int("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881"
                  "FF2F2D82C68528AA6056583A48F3", 16)
    for bad in (bytes(core.EC_PT), b"\x02" + pt[1:], b"\x04" + bytes(128), pt[:-1] + bytes([pt[-1] ^ 1]),
                b"\x04" + p_field.to_bytes(64, "big") + pt[65:], b"\x04" + pt[1:65] + bytes(64)):
        with pytest.raises(SigillumError):
            core.hkem_check_pk(pk[:-core.EC_PT] + bad)
    core.hkem_check_pk(pk)


def test_r2_4_bad_announcement_rejected_on_receive(monkeypatch):
    a, b, fa, fb = pair()
    real = core.HybridKey.generate

    class Fake:
        def __init__(self):
            k = real()
            self.seed, self.pk = k.seed, k.pk[:-core.EC_PT] + b"\x04" + bytes(128)
    monkeypatch.setattr(core.HybridKey, "generate", staticmethod(Fake))
    blob = ratchet.encrypt("x", a, fb)
    monkeypatch.setattr(core.HybridKey, "generate", real)
    before = json.dumps(b.state, sort_keys=True)
    with pytest.raises(SigillumError):
        ratchet.decrypt(blob, b)
    assert json.dumps(b.state, sort_keys=True) == before


def test_state_strictly_validated():
    """v11: kein Übernehmen alter Zustandsformen mehr – jede Abweichung wird abgelehnt."""
    for bad in (["3F2A-91C0-7D4E-B812"], {"x": 5}):
        a = mk("Anna", PWA)
        a.state["sheets"] = bad
        with pytest.raises(SigillumError):
            ratchet.Vault.open(a.to_blob(), PWA, "481937", KF)


# ------------------------------------------------------------------ dritte Prüfrunde
def test_r3_1_duplicate_reported_and_changes_nothing():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hallo", a, fb), b)
    ratchet.decrypt(ratchet.encrypt("antwort", b, fa), a)
    m = ratchet.encrypt("Treffen 14:30", a, fb)
    r1 = ratchet.decrypt(m, b)
    assert not r1["duplicate"]
    before = json.dumps(b.state, sort_keys=True)
    # R12-N1: der Einmal-Schlüssel ist gelöscht – die Wiederholung wird erkannt, der Inhalt ist nicht mehr lesbar
    with pytest.raises(SigillumError, match="schon geöffnet"):
        ratchet.decrypt(m, b)
    assert json.dumps(b.state, sort_keys=True) == before


def test_r3_1_duplicate_inside_one_batch():
    a, b, fa, fb = pair()
    m = ratchet.encrypt("eins", a, fb)
    out = ratchet.process_batch([(1, m), (2, m)], b)
    flags = sorted(o["result"]["duplicate"] for o in out)
    assert flags == [False, True]


def test_r3_1b_replay_after_reset_rejected():
    a, b, fa, fb = pair()
    first = ratchet.encrypt("erste", a, fb, now=1000)
    ratchet.decrypt(first, b)
    for i in range(3):
        ratchet.decrypt(ratchet.encrypt(f"b{i}", b, fa), a)
        ratchet.decrypt(ratchet.encrypt(f"a{i}", a, fb, now=2000 + i), b)
    ratchet.reset_contact(b, fa)
    r = ratchet.decrypt(first, b)
    assert r["duplicate"] and not r["partner_key_updated"]
    assert fa not in b.state["contacts"] or b.state["contacts"][fa]["their"] is None


def test_r3_1b_old_unseen_base_message_after_reset_is_replay():
    """Auch eine nie gesehene, aber ältere Erstnachricht wird nach dem Neustart nicht übernommen."""
    a, b, fa, fb = pair()
    old = ratchet.encrypt("alt", a, fb, now=500)              # nie zugestellt
    ratchet.reset_contact(a, fb)
    ratchet.decrypt(ratchet.encrypt("neu", a, fb, now=1000), b)
    ratchet.reset_contact(b, fa)
    r = ratchet.decrypt(old, b)
    assert r["replay"] and not r["partner_key_updated"]


def test_r3_1b_partner_restart_still_works_after_my_reset():
    """Echter Neustart des Partners (neuerer Zeitstempel) wird weiterhin angenommen."""
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("eins", a, fb, now=1000), b)
    ratchet.reset_contact(b, fa)
    ratchet.reset_contact(a, fb)
    r = ratchet.decrypt(ratchet.encrypt("neu", a, fb, now=3000), b)
    assert r["partner_key_updated"] and not r["replay"]
    assert ratchet.decrypt(ratchet.encrypt("antwort", b, fa), a)["text"] == "antwort"


def test_r3_seen_register_bounded_and_persisted():
    a, b, fa, fb = pair()
    for i in range(5):
        ratchet.decrypt(ratchet.encrypt(f"m{i}", a, fb), b)
    v = ratchet.Vault.open(b.to_blob(), PWB, "481937", KF)
    assert len(v.state["seen"][fa]["ids"]) == 5
    b.state["seen"][fa]["ids"] = ["x"] * ratchet.MAX_SEEN
    ratchet.decrypt(ratchet.encrypt("n", a, fb), b)
    assert len(b.state["seen"][fa]["ids"]) == ratchet.MAX_SEEN


def test_r3_register_validation():
    for bad in ({"seen": {"x": {"ids": "nope", "ts": 0}}}, {"seen": []}, {"seen": {"x": {"ids": [], "ts": "0"}}},
                {"sheets_opened": {"x": -1}}, {"sheets_opened": {"x": True}}):
        a = mk("Anna", PWA)
        a.state.update(bad)
        with pytest.raises(SigillumError):
            ratchet.Vault.open(a.to_blob(), PWA, "481937", KF)


def test_r3_missing_state_fields_rejected():
    for field in ("seen", "sheets_opened", "partners", "chk"):
        a = mk("Anna", PWA)
        del a.state[field]
        with pytest.raises(SigillumError):
            ratchet.Vault.open(a.to_blob(), PWA, "481937", KF)


def test_r3_future_timestamp_does_not_block_restart(monkeypatch):
    """Falsche Uhr beim Partner (weit in der Zukunft) sperrt einen späteren Neustart nicht dauerhaft."""
    a, b, fa, fb = pair()
    t0 = time.time()
    ratchet.decrypt(ratchet.encrypt("zukunft", a, fb, now=t0 + 10 ** 9), b)
    assert b.state["contacts"][fa]["last_ts"] <= t0 + ratchet.MAX_SKEW + 1
    ratchet.reset_contact(b, fa)
    ratchet.reset_contact(a, fb)
    later = t0 + 3600                                         # eine Stunde später, Uhr wieder richtig
    monkeypatch.setattr(ratchet.time, "time", lambda: later)
    r = ratchet.decrypt(ratchet.encrypt("neu", a, fb, now=later), b)
    assert r["partner_key_updated"] and not r["replay"]
