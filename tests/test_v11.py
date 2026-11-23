"""Version 11: Alltags-Hülle (YubiKey ohne Passphrase), Nachweis aller Faktoren, Partner, versiegelte Sitzung."""
import json
import secrets
import struct

import pytest

from sigillum import core, ratchet
from sigillum.core import SigillumError
from softtoken import SoftToken

KF = core.new_keyfile()
PW = "abacus zoom kettle velvet ample cactus"
PIN = "246813"
PARTNER_KF = core.new_keyfile()
PARTNER_PW = "zoom velvet cactus ample kettle abacus yo-yo"


def make(fido=True):
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    tok = SoftToken()
    code = v.new_code()
    if fido:
        salt = v.new_prf_salt()
        v.protect(salt, [tok.enroll(salt)], code, v.full_keys(PW, PIN, KF))
    return v, tok, code


# ------------------------------------------------------------------ Alltags-Hülle
def test_daily_unlock_without_passphrase():
    v, tok, code = make()
    blob = v.to_blob()
    d = ratchet.Vault.open(blob, None, PIN, KF, prf_fn=tok.derive)
    assert d.fido and d.identity.public().fp() == v.identity.public().fp()
    assert d._key is None and d._dkey is not None                 # im Alltag ist A (Passphrase) unbekannt
    assert d.to_blob()                                             # Speichern geht ohne A (Inhalt mit M)


@pytest.mark.parametrize("case", ["pin", "keyfile", "token", "no_token"])
def test_daily_unlock_every_factor_required(case):
    v, tok, code = make()
    blob = v.to_blob()
    other = SoftToken()
    other.creds = {c: b"\x00" * 32 for c in tok.creds}
    kw = {"prf_fn": tok.derive}
    pin, kf = PIN, KF
    if case == "pin":
        pin = "999999"
    elif case == "keyfile":
        kf = core.new_keyfile()
    elif case == "token":
        kw = {"prf_fn": other.derive}
    else:
        kw = {}
    with pytest.raises(SigillumError):
        ratchet.Vault.open(blob, PW, pin, kf, **kw)


def test_notfall_needs_passphrase_and_slots_not_interchangeable():
    v, tok, code = make()
    blob = v.to_blob()
    assert ratchet.Vault.open(blob, PW, PIN, KF, code=code).opened_with_code
    with pytest.raises(SigillumError):
        ratchet.Vault.open(blob, None, PIN, KF, code=code)
    # Hülle vertauschen: Notfall-Code in die Alltags-Hülle / YubiKey-Geheimnis in die Notfall-Hülle -> nichts geht
    h = ratchet.parse_fido_header(blob)
    daily = next(s for s in h["slots"] if s["type"] == ratchet.SLOT_DAILY)
    a = core.derive_key(PW, PIN, KF, h["salt"], core.PURPOSE_IDENTITY)
    d = core.derive_daily_key(PIN, KF, h["salt"])
    prf = tok.derive([daily["meta"]], h["prf_salt"])[1]
    for slot, base, secret in ((daily, d, code[1]), (daily, a, prf),
                               (next(s for s in h["slots"] if s["type"] == ratchet.SLOT_CODE), d, code[1])):
        with pytest.raises(SigillumError):
            core._aead_decrypt(slot["wrapped"], ratchet._slot_aad(h["header"][:6], h["salt"], h["prf_salt"],
                                                                   slot["type"], slot["meta"]),
                               slot["nonce"], ratchet._slot_kek(base, secret, slot["type"], slot["meta"]))


def test_daily_key_domain_separated():
    salt = bytes(16)
    a = core.derive_key(PW, PIN, KF, salt, core.PURPOSE_IDENTITY)
    d = core.derive_daily_key(PIN, KF, salt)
    q = core.derive_quick_key(PIN, salt)
    assert len({a, d, q}) == 3
    assert core.derive_daily_key(PIN, KF, salt) == d and core.derive_daily_key("246814", KF, salt) != d


def test_legacy_fido_slot_rejected_with_clear_message():
    v, tok, code = make()
    h = ratchet.parse_fido_header(v.to_blob())
    slots = [dict(s, type=ratchet.SLOT_LEGACY_FIDO) if s["type"] == ratchet.SLOT_DAILY else s for s in h["slots"]]
    blob = ratchet._fido_header(h["salt"], h["prf_salt"], slots, h["nonce"]) + h["ct"]
    with pytest.raises(SigillumError, match="älteren App-Version"):
        ratchet.parse_fido_header(blob)


# ------------------------------------------------------------------ Nachweis aller Faktoren (Schritt-Bestätigung)
def test_full_keys_checks_every_factor():
    v, tok, code = make()
    d = ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)
    a, a2 = d.full_keys(PW, PIN, KF)
    assert a == core.derive_key(PW, PIN, KF, d.salt, core.PURPOSE_IDENTITY) and a2 == d._dkey
    for pw, pin, kf in ((PW.replace("zoom", "zone"), PIN, KF), (PW, "999999", KF), (PW, PIN, core.new_keyfile())):
        with pytest.raises(SigillumError):
            d.full_keys(pw, pin, kf)


def test_protect_and_unprotect_need_full_keys():
    v, tok, code = make()
    d = ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)
    salt = d.new_prf_salt()
    with pytest.raises(SigillumError):
        d.protect(salt, [tok.derive(d.fido_cred_ids(), salt)], d.new_code(), (bytes(32), bytes(32)))
    with pytest.raises(SigillumError):
        d.unprotect((bytes(32), bytes(32)))
    d.unprotect(d.full_keys(PW, PIN, KF))
    m3 = d.to_blob()
    assert ratchet.file_mode(m3) == core.MODE_IDENTITY
    assert ratchet.Vault.open(m3, PW, PIN, KF).identity.public().fp() == v.identity.public().fp()


def test_renew_in_daily_session_keeps_identity_and_invalidates_old_code():
    v, tok, code = make()
    d = ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)
    salt = d.new_prf_salt()
    new_code = d.new_code()
    d.protect(salt, [tok.derive(d.fido_cred_ids(), salt)], new_code, d.full_keys(PW, PIN, KF))
    blob = d.to_blob()
    assert ratchet.Vault.open(blob, None, PIN, KF, prf_fn=tok.derive).fido
    assert ratchet.Vault.open(blob, PW, PIN, KF, code=new_code).fido
    with pytest.raises(SigillumError):
        ratchet.Vault.open(blob, PW, PIN, KF, code=code)


def test_same_passphrase_works_without_passphrase_in_session():
    v, tok, code = make()
    d = ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)
    assert d.same_passphrase(PW) and d.same_passphrase(PW.upper() + "  ") and not d.same_passphrase(PARTNER_PW)


def test_check_values_in_encrypted_content_only():
    v, tok, code = make()
    blob = v.to_blob()
    for x in (v.state["chk"]["a"], v.state["chk"]["d"], v.state["chk"]["pw"], v.state["chk"]["pw_salt"]):
        assert x.encode() not in blob and bytes.fromhex(x) not in blob


def test_tampered_a_check_rejected():
    v, _, _ = make(fido=False)
    v.state["chk"]["a"] = "00" * 32
    with pytest.raises(SigillumError, match="Prüfwert"):
        ratchet.Vault.open(v.to_blob(), PW, PIN, KF)


def test_tampered_d_check_rejected_daily():
    v, tok, _ = make()
    v.state["chk"]["d"] = "00" * 32
    with pytest.raises(SigillumError, match="Prüfwert"):
        ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)


def test_protect_rejects_wrong_a2():
    """Befund R11-H-c: ein falsches A2 darf keine unbrauchbare Alltags-Hülle erzeugen."""
    v, tok, _ = make(fido=False)
    a, d = v.full_keys(PW, PIN, KF)
    salt = v.new_prf_salt()
    for bad in ((a, secrets.token_bytes(32)), (a, a), (d, d)):
        with pytest.raises(SigillumError):
            v.protect(salt, [tok.enroll(salt)], v.new_code(), bad)
    assert not v.fido
    v.protect(salt, [tok.enroll(salt)], v.new_code(), (a, d))
    assert ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive).fido


def test_identity_from_11_0_without_d_check_still_opens_and_gets_it():
    """11.0 -> 11.1: Identitäten ohne chk.d öffnen weiter; der Prüfwert entsteht erst, wenn A2 bewiesen ist."""
    v, tok, _ = make()
    d_ok = v.state["chk"]["d"]
    del v.state["chk"]["d"]
    w = ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)         # Alltag beweist A2
    assert w.state["chk"]["d"] == d_ok
    m3, _, _ = make(fido=False)
    del m3.state["chk"]["d"]
    x = ratchet.Vault.open(m3.to_blob(), PW, PIN, KF)
    assert "d" not in x.state["chk"]
    salt = x.new_prf_salt()
    with pytest.raises(SigillumError):                                            # ohne Nachweis kein Schreiben
        x.protect(salt, [tok.enroll(salt)], x.new_code(), (x._key, secrets.token_bytes(32)))
    x.protect(salt, [tok.enroll(salt)], x.new_code(), x.full_keys(PW, PIN, KF))    # Nachweis setzt chk.d
    assert ratchet.Vault.open(x.to_blob(), None, PIN, KF, prf_fn=tok.derive).fido
    v.state["chk"]["d"] = "zz" * 32
    with pytest.raises(SigillumError):
        ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)


def _partner_state(v, **change):
    pid = v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135790")
    v.state["partners"][pid].update(change)
    return v


@pytest.mark.parametrize("change", [{"pw": ""}, {"pin": ""}, {"pin": "12345"}, {"pw": "ich bin ein satz"},
                                    {"pw": PW}, {"name": ""}, {"name": "Ben\u202e"}, {"pw": PARTNER_PW.upper()},
                                    {"created": -1}])
def test_partner_entries_checked_on_load(change):
    """Befund R11-9a: beim Laden gelten dieselben Regeln wie beim Anlegen (auch H1: nie die eigene Passphrase)."""
    v, _, _ = make(fido=False)
    _partner_state(v, **change)
    with pytest.raises(SigillumError):
        ratchet.Vault.open(v.to_blob(), PW, PIN, KF)


def test_partner_entry_valid_loads_and_limit():
    v, _, _ = make(fido=False)
    _partner_state(v)
    assert len(ratchet.Vault.open(v.to_blob(), PW, PIN, KF).partners()) == 1
    e = next(iter(v.state["partners"].values()))
    for i in range(ratchet.MAX_PARTNERS):
        v.state["partners"][f"{i:016x}"] = dict(e)
    with pytest.raises(SigillumError):
        ratchet.Vault.open(v.to_blob(), PW, PIN, KF)


# ------------------------------------------------------------------ Partner (Variante C)
def test_partner_roundtrip_and_shared_message():
    v, tok, code = make()
    pid = v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135790")
    d = ratchet.Vault.open(v.to_blob(), None, PIN, KF, prf_fn=tok.derive)
    name, pw, pin, kf = d.partner(pid)
    assert (name, kf, pin) == ("Ben", PARTNER_KF, "135790")
    blob = core.encrypt_shared("hallo", pw, pin, kf, b"\x01" * 16)
    assert core.decrypt_shared(blob, PARTNER_PW, "135790", PARTNER_KF)["text"] == "hallo"
    assert [p[1] for p in d.partners()] == ["Ben"]
    d.touch_partner(pid, 1234)
    assert d.partners()[0][3] == 1234
    d.remove_partner(pid)
    assert d.partners() == []


def test_partner_rules_h1_and_duplicates():
    v, _, _ = make()
    with pytest.raises(SigillumError, match="Identität"):
        v.add_partner("Ben", KF, PARTNER_PW, "135790")                    # Identitäts-Schlüsseldatei
    with pytest.raises(SigillumError, match="Identität"):
        v.add_partner("Ben", PARTNER_KF, PW, "135790")                    # Identitäts-Passphrase
    with pytest.raises(SigillumError):
        v.add_partner("Ben", PARTNER_KF, "zu kurz", "135790")             # keine Diceware-Passphrase
    with pytest.raises(SigillumError):
        v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135")              # PIN zu kurz
    v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135790")
    with pytest.raises(SigillumError, match="schon"):
        v.add_partner("Carl", PARTNER_KF, PARTNER_PW, "135790")           # gleicher Schlüssel
    with pytest.raises(SigillumError, match="Namen"):
        v.add_partner("Веn", core.new_keyfile(), PARTNER_PW, "135790")    # kyrillisch gemischt / Doppelgänger


def test_partner_entries_strictly_validated():
    v, _, _ = make(fido=False)
    pid = v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135790")
    for field, val in (("kf", "zz"), ("kf", (b"\x00" * 44).hex()), ("created", "x"), ("pin", 5), ("extra", 1)):
        w = ratchet.Vault.open(v.to_blob(), PW, PIN, KF)
        w.state["partners"][pid][field] = val
        with pytest.raises(SigillumError):
            ratchet.Vault.open(w.to_blob(), PW, PIN, KF)


def test_partner_secrets_not_in_file_plaintext():
    v, _, _ = make()
    v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135790")
    blob = v.to_blob()
    assert PARTNER_KF not in blob and PARTNER_KF.hex().encode() not in blob and b"zoom velvet" not in blob


# ------------------------------------------------------------------ versiegelte Sitzung (Schnell-Entsperren)
def test_session_seal_roundtrip_and_wrong_pin():
    v, tok, code = make()
    v.add_partner("Ben", PARTNER_KF, PARTNER_PW, "135790")
    salt = secrets.token_bytes(core.SALT_LEN)
    k = core.derive_quick_key(PIN, salt)
    sealed = core.seal(k, v.session_bytes(), b"SIGILLUM-v11-quick")
    w = ratchet.Vault.from_session(core.unseal(core.derive_quick_key(PIN, salt), sealed, b"SIGILLUM-v11-quick"))
    assert w.to_blob() and w.identity.public().to_bytes() == v.identity.public().to_bytes()
    assert ratchet.Vault.open(w.to_blob(), None, PIN, KF, prf_fn=tok.derive).partners()[0][1] == "Ben"
    with pytest.raises(SigillumError):
        core.unseal(core.derive_quick_key("999999", salt), sealed, b"SIGILLUM-v11-quick")
    with pytest.raises(SigillumError):
        core.unseal(k, sealed, b"anderer-zweck")


def test_session_bytes_tamper_rejected():
    v, _, _ = make()
    d = json.loads(v.session_bytes())
    d["state"]["chk"] = {}
    with pytest.raises(SigillumError):
        ratchet.Vault.from_session(json.dumps(d).encode())
    with pytest.raises(SigillumError):
        ratchet.Vault.from_session(b"\xff\x00")


def test_session_key_lengths_checked():
    """Befund R11-H-d: falsche Schlüssel- und Salzlängen werden abgelehnt."""
    v, _, _ = make()
    good = json.loads(v.session_bytes())
    ratchet.Vault.from_session(json.dumps(good).encode())
    for field, val in (("key", "00"), ("dkey", "00" * 31), ("salt", "00" * 3), ("kf", 5), ("key", None)):
        d = json.loads(json.dumps(good))
        d[field] = val
        if field == "key" and val is None and d["prot"] is not None:
            continue
        with pytest.raises(SigillumError):
            ratchet.Vault.from_session(json.dumps(d).encode())


def test_min_pin_six():
    with pytest.raises(SigillumError):
        core.check_pin("12345")
    core.check_pin("123456")
    with pytest.raises(SigillumError):
        ratchet.Vault.create("Anna", PW, "12345", KF)
