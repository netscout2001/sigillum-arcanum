"""Befunde der elften Prüfrunde (R12): Passphrase-Stärke, naheliegende PINs, Generationszähler."""
import pytest

from sigillum import core, ratchet
from sigillum.core import SigillumError

KF = core.new_keyfile()


@pytest.mark.parametrize("pw", ["password " * 6, "abacus abacus abacus abacus abacus abacus",
                                "abacus zoom kettle velvet ample abacus", "abacus zoom kettle velvet ample"])
# (7 Wörter mit EINER Wiederholung = 6 verschiedene bleiben gültig: so konnte der Generator bis 11.1 ziehen, R14-N5)
def test_weak_or_repeated_passphrases_rejected(pw):
    with pytest.raises(SigillumError):
        core.check_passphrase(pw)


def test_passphrase_bits_count_distinct_words_only():
    assert core.passphrase_bits("password " * 6) == 0.0
    assert core.passphrase_bits("abacus zoom abacus zoom abacus zoom") < 26       # nur 2 verschiedene Wörter
    assert abs(core.MIN_PASSPHRASE_BITS - 77.546) < 0.01


def test_generator_never_repeats_words():
    for _ in range(3000):
        w = core.generate_passphrase(7).split(" ")
        assert len(set(w)) == 7
    core.check_passphrase(core.generate_passphrase(6))
    core.check_passphrase(core.generate_passphrase(7))


def test_stored_partner_passphrase_with_old_duplicate_still_loads():
    """Kein Aussperren: bis 11.1 konnte der Generator ein Wort doppelt ziehen."""
    core.check_passphrase_stored("abacus zoom kettle velvet ample cactus zoom")
    core.check_passphrase_stored("abacus " * 6)              # R14-M1: exakt die alte Regel – nie aussperren
    assert core.passphrase_is_weak("abacus " * 6) and not core.passphrase_is_weak(core.generate_passphrase())
    with pytest.raises(SigillumError):
        core.check_passphrase_stored("ich bin ein satz der nicht passt")


@pytest.mark.parametrize("pin", ["000000", "111111", "123456", "654321", "890123", "121212", "123123", "abcdef",
                                 "qwertz", "010190", "311299", "24121985", "19851224", "12345"])
def test_obvious_pins_rejected_for_new_identity(pin):
    assert core.pin_problem(pin)
    with pytest.raises(SigillumError):
        ratchet.Vault.create("Anna", core.generate_passphrase(7), pin, KF)


@pytest.mark.parametrize("pin", ["481937", "246813", "864209", "k7Rp2x", "39 18 47"])
def test_random_pins_accepted(pin):
    assert core.pin_problem(pin) is None


def test_generated_pins_never_obvious():
    for _ in range(3000):
        assert core.pin_problem(core.generate_pin(6)) is None


def test_existing_weak_pin_still_opens():
    """Bestehende Identitäten mit naheliegender PIN öffnen weiter (nur ein Hinweis in der Oberfläche)."""
    pw = core.generate_passphrase(7)
    v = ratchet.Vault.create("Anna", pw, "481937", KF)
    blob = v.to_blob()
    assert ratchet.Vault.open(blob, pw, "481937", KF)


def test_generation_counts_every_write_and_is_authenticated():
    pw = core.generate_passphrase(7)
    v = ratchet.Vault.create("Anna", pw, "481937", KF)
    b1 = v.to_blob()
    b2 = v.to_blob()
    g1 = ratchet.Vault.open(b1, pw, "481937", KF).gen
    g2 = ratchet.Vault.open(b2, pw, "481937", KF).gen
    assert g2 == g1 + 1 >= 2
    v.state["gen"] = -1
    with pytest.raises(SigillumError):
        ratchet.Vault.open(_raw(v), pw, "481937", KF)


def _raw(v):
    """Datei mit ungültigem Zähler (ohne die Erhöhung in to_blob) – muss abgelehnt werden."""
    import json
    import secrets
    st = json.dumps(v.state, separators=(",", ":"), sort_keys=True).encode()
    raw = ratchet.STATE_MAGIC + core._lp(v.identity.name.encode()) + v.identity.secret_bytes() + core._lp(st)
    nonce = secrets.token_bytes(core.NONCE_LEN)
    header = core._shared_header(core.MODE_IDENTITY, core.KDF_OPS, core.KDF_MEMLOG, v.salt, nonce)
    return header + core._aead_encrypt(raw, header, nonce, v._key)


def test_old_file_without_gen_opens_as_zero():
    pw = core.generate_passphrase(7)
    v = ratchet.Vault.create("Anna", pw, "481937", KF)
    v.state.pop("gen", None)
    w = ratchet.Vault.open(_raw(v), pw, "481937", KF)
    assert w.gen == 0


# ------------------------------------------------------------------ R12-N1: Einmal-Schlüssel je Nachricht
import secrets as _secrets  # noqa: E402
import struct  # noqa: E402

from test_ratchet import pair  # noqa: E402


def test_each_message_in_a_row_gets_its_own_key_until_pool_used():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hallo", a, fb), b)               # Ben kennt jetzt Annas Vorrat
    assert ratchet.once_keys_left(b, fa) == ratchet.POOL - 1
    msgs = [ratchet.encrypt(f"B{i}", b, fa) for i in range(ratchet.POOL + 2)]
    assert ratchet.once_keys_left(b, fa) == 0
    seeds_before = {k["id"]: k["seed"] for k in a.state["contacts"][fb]["my_keys"]}
    used = []
    for i, m in enumerate(msgs):
        r = ratchet.decrypt(m, a)
        assert r["text"] == f"B{i}"
        used.append(r["key"])
    left = {k["id"] for k in a.state["contacts"][fb]["my_keys"]}
    gone = set(seeds_before) - left
    assert len(gone) == ratchet.POOL - 1                               # alle Einmal-Schlüssel gelöscht
    blob = a.to_blob()
    for kid in gone:                                                   # Privatschlüssel nicht mehr in der Datei
        assert seeds_before[kid] not in json_state(a)
    assert blob


def json_state(v):
    import json
    return json.dumps(v.state)


def test_forward_secrecy_per_message_after_compromise():
    """Wer NACH dem Lesen von Nachricht 1 Annas Identität erbeutet, kann sie nicht mehr entschlüsseln."""
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hallo", a, fb), b)
    m1 = ratchet.encrypt("geheim 1", b, fa)
    m2 = ratchet.encrypt("geheim 2", b, fa)
    ratchet.decrypt(m1, a)
    stolen = a.clone()                                                 # Zustand nach dem Lesen von m1
    import pytest as _p
    with _p.raises(SigillumError):
        ratchet.decrypt(m1, stolen)
    assert ratchet.decrypt(m2, stolen)["text"] == "geheim 2"           # noch ungelesene Nachricht: ja (unvermeidbar)


def test_out_of_order_within_pool():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hallo", a, fb), b)
    m = [ratchet.encrypt(f"B{i}", b, fa) for i in range(3)]
    assert ratchet.decrypt(m[2], a)["text"] == "B2"
    assert ratchet.decrypt(m[0], a)["text"] == "B0"
    assert ratchet.decrypt(m[1], a)["text"] == "B1"


def test_pool_announcement_tamper_and_shape():
    a, b, fa, fb = pair()
    m = ratchet.encrypt("x", a, fb)
    assert m[3] == core.MODE_CONTACT_POOL
    assert len(m) > ratchet.HDR_LEN + ratchet.PLAIN_FIXED_POOL
    bad = bytearray(m)
    bad[3] = core.MODE_CONTACT
    with pytest.raises(SigillumError):
        ratchet.decrypt(bytes(bad), b)


def _encrypt_v4(text, vault, recip_fp):
    """Nachricht wie App-Version 11.1 (Modus 4, EIN angekündigter Schlüssel) – zum Prüfen der Verträglichkeit."""
    recip, _ = vault.contact(recip_fp)
    me = vault.identity
    my_fp = me.public().fp_raw()
    cs = vault.state["contacts"].setdefault(recip_fp, ratchet._empty(recip))
    their = cs["their"]
    if their:
        k = ratchet._their_keys(their)[-1]
        t_id, t_pk = bytes.fromhex(k["id"]), bytes.fromhex(k["pk"])
    else:
        t_id, t_pk = ratchet.BASE_ID, recip.kem_pk
    nk = core.HybridKey.generate()
    seq, kid = cs["next_seq"], _secrets.token_bytes(8)
    announce = struct.pack(">Q", seq) + kid + nk.pk
    inner, _ = core.pack_inner(text, my_fp[:16])
    ss, kem_ct = core.hkem_encap(t_pk)
    nonce = _secrets.token_bytes(core.NONCE_LEN)
    header = core.MAGIC + bytes([core.VERSION, core.MODE_CONTACT]) + kem_ct + nonce
    signed = ratchet._signed_data(header, recip.fp_raw(), my_fp, announce, inner)
    plain = my_fp + me.sign(signed, ratchet.SIG_CONTEXT) + announce + inner
    blob = header + core._aead_encrypt(plain, header, nonce, ratchet._msg_key(ss, header, recip.fp_raw(), t_id))
    cs["my_keys"].append({"seq": seq, "id": kid.hex(), "seed": nk.seed.hex(), "created": 0})
    cs["next_seq"] = seq + 1
    return blob


def test_messages_from_11_1_still_read_and_answered():
    a, b, fa, fb = pair()
    r = ratchet.decrypt(_encrypt_v4("alt 1", a, fb), b)                # 11.1-Absender -> 11.2-Empfänger
    assert r["text"] == "alt 1"
    assert ratchet.decrypt(ratchet.encrypt("neu", b, fa), a)["text"] == "neu"    # Antwort an den EINEN Schlüssel
    assert ratchet.decrypt(ratchet.encrypt("neu 2", b, fa), a)["text"] == "neu 2"
    r = ratchet.decrypt(_encrypt_v4("alt 2", a, fb), b)
    assert r["text"] == "alt 2"
    # Zustand aus 11.1 ({"seq","id","pk"}) wird beim Senden weiter benutzt
    their = b.state["contacts"][fa]["their"]
    assert "keys" in their or "id" in their


def test_foreign_vectors_checked_and_tamper_detected(monkeypatch, tmp_path):
    """R12-H4: Selbsttest prüft Werte fremder Implementierungen; ein verfälschter Wert lässt ihn scheitern."""
    import json
    import os
    core._foreign_vectors()
    src = os.path.join(core._HERE, "data", "kat_fremd.json")
    v = json.load(open(src, encoding="utf-8"))
    for key in ("ecdsa_sig", "mldsa_sig", "mldsa_pk_sha3"):
        bad = dict(v)
        bad[key] = ("00" if bad[key][:2] != "00" else "01") + bad[key][2:]
        d = tmp_path / key
        (d / "data").mkdir(parents=True)
        (d / "data" / "kat_fremd.json").write_text(json.dumps(bad), encoding="utf-8")
        monkeypatch.setattr(core, "_HERE", str(d))
        with pytest.raises(Exception):
            core._foreign_vectors()
    bad = json.loads(json.dumps(v))
    bad["argon2id"]["out"] = "00" * 32
    d = tmp_path / "argon"
    (d / "data").mkdir(parents=True)
    (d / "data" / "kat_fremd.json").write_text(json.dumps(bad), encoding="utf-8")
    monkeypatch.setattr(core, "_HERE", str(d))
    with pytest.raises(ValueError):
        core._foreign_vectors()



# ------------------------------------------------------------------ Runde 14 (Nachprüfung der Behebung)
def test_r14_m1_identity_with_weak_stored_partner_still_opens():
    pw = core.generate_passphrase(7)
    v = ratchet.Vault.create("Anna", pw, "481937", KF)
    v.state["partners"]["00112233aabbccdd"] = {"name": "Gleich", "kf": core.new_keyfile().hex(), "pw": "abacus " * 5
                                               + "abacus", "pin": "246813", "created": 1, "last_used": 0}
    v.state["partners"]["00112233aabbccdd"]["pw"] = core.canonical_passphrase("abacus " * 6)
    w = ratchet.Vault.open(v.to_blob(), pw, "481937", KF)
    assert w.weak_partners() == ["Gleich"]


@pytest.mark.parametrize("pin", ["1²3456", "²³⁴⁵⁶⁷", "①②③④⑤⑦", "١٢٣٤٥٦", "𝟏𝟐𝟑𝟒𝟓𝟔"])
def test_r14_m2_pin_check_never_crashes(pin):
    core.pin_problem(pin)                                   # darf nie werfen


def test_r14_m2_seven_word_with_one_repeat_still_valid():
    core.check_passphrase("abacus zoom kettle velvet ample cactus zoom")


@pytest.mark.parametrize("pin", ["000001", "100000", "123654", "789456", "456123", "159357", "741852", "666999",
                                 "777888", "1q2w3e", "qwe123", "123abc", "a1b2c3", "passw0rd", "hallo123",
                                 "1 2 3 4 5 6", "123-456", "12.12.1985", "01.01.2000", "1985-12-24", "123321"])
def test_r14_n3_more_obvious_pins(pin):
    assert core.pin_problem(pin)


def test_r14_n1_no_false_risk_when_only_once_key_deleted():
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hallo", b, fa), a)            # Anna kennt Bens Vorrat
    a1 = ratchet.encrypt("a1", a, fb)
    a2 = ratchet.encrypt("a2", a, fb)
    r2 = ratchet.decrypt(a2, b)
    assert r2["gap_count"] == 1 and not r2["risk"]                  # a1 bleibt lesbar – keine Warnung
    assert ratchet.decrypt(a1, b)["text"] == "a1"


def test_r14_n4_newest_key_tried_first_and_batch_uses_hint(monkeypatch):
    a, b, fa, fb = pair()
    ratchet.decrypt(ratchet.encrypt("hallo", a, fb), b)
    for _ in range(30):                                            # viele offene eigene Schlüssel bei Anna
        last = ratchet.encrypt("x", a, fb)
    ratchet.decrypt(last, b)                                       # Ben antwortet auf Annas neueste Ankündigung
    m = ratchet.encrypt("an neuesten", b, fa)
    calls = []
    orig = core.HybridKey.decap

    def counting(self, ct):
        calls.append(1)
        return orig(self, ct)
    monkeypatch.setattr(core.HybridKey, "decap", counting)
    out = ratchet.process_batch([(1, m)], a)
    assert out[0]["result"]["text"] == "an neuesten"
    assert len(calls) <= 1 + ratchet.POOL + 1                       # nicht alle ~150 Schlüssel; zweiter Lauf: 1
