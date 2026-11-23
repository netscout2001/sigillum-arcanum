"""YubiKey-Schutz der Identität (Modus 5), Notfall-Paket, FIDO-Adapter."""
import itertools

import pytest

from sigillum import core, fidokey, notfall, ratchet, shamir
from sigillum.core import SigillumError
from softtoken import SoftToken

KF = core.new_keyfile()
PW = "abacus zoom kettle velvet ample cactus"
PIN = "481937"


def full(v):
    return v.full_keys(PW, PIN, KF)


def setup_vault(tok=None):
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    tok = tok or SoftToken()
    salt = v.new_prf_salt()
    cid, prf = tok.enroll(salt)
    code = v.new_code()
    v.protect(salt, [(cid, prf)], code, full(v))
    return v, tok, code


def open_fido(blob, tok, pw=PW, pin=PIN, kf=KF):
    return ratchet.Vault.open(blob, pw, pin, kf, prf_fn=tok.derive)


# ------------------------------------------------------------------ Grundfunktion
def test_mode5_roundtrip_with_key_and_code():
    v, tok, code = setup_vault()
    v.state["book"]["x"] = {"name": "n"}
    blob = v.to_blob()
    assert ratchet.file_mode(blob) == core.MODE_IDENTITY_FIDO
    a = open_fido(blob, tok)
    assert a.fido and not a.opened_with_code and a.state["book"]["x"] == {"name": "n"}
    b = ratchet.Vault.open(blob, PW, PIN, KF, code=code)
    assert b.opened_with_code
    assert a.identity.public().fp() == b.identity.public().fp() == v.identity.public().fp()


def test_mode5_needs_key_or_code():
    v, tok, code = setup_vault()
    blob = v.to_blob()
    with pytest.raises(SigillumError, match="YubiKey"):
        ratchet.Vault.open(blob, PW, PIN, KF)


def test_mode5_every_factor_required():
    v, tok, code = setup_vault()
    blob = v.to_blob()
    other = SoftToken()
    other.creds = {c: b"\x00" * 32 for c in tok.creds}          # gleiche Kennung, anderes Geheimnis
    for args, kw in [((blob, PW, "999999", KF), {"prf_fn": tok.derive}),
                     ((blob, PW.replace("zoom", "zone"), PIN, KF), {"code": code}),
                     ((blob, None, PIN, KF), {"code": code}),
                     ((blob, PW, PIN, core.new_keyfile()), {"prf_fn": tok.derive}),
                     ((blob, PW, PIN, KF), {"prf_fn": other.derive}),
                     ((blob, PW, PIN, KF), {"code": (code[0], bytes(32))}),
                     ((blob, PW, "999999", KF), {"code": code})]:
        with pytest.raises(SigillumError):
            ratchet.Vault.open(*args, **kw)


def test_foreign_key_and_foreign_package_rejected():
    v, tok, code = setup_vault()
    blob = v.to_blob()
    with pytest.raises(SigillumError, match="gehört nicht"):
        open_fido(blob, SoftToken())
    with pytest.raises(SigillumError, match="Notfall-Paket gehört nicht"):
        ratchet.Vault.open(blob, PW, PIN, KF, code=ratchet.Vault.new_code())


def test_fingerprint_and_messages_unchanged_by_protection():
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    fp = v.identity.public().fingerprint()
    tok = SoftToken()
    salt = v.new_prf_salt()
    v.protect(salt, [tok.enroll(salt)], v.new_code(), full(v))
    assert open_fido(v.to_blob(), tok).identity.public().fingerprint() == fp


# ------------------------------------------------------------------ Format und Manipulation
def test_every_header_byte_flip_rejected():
    v, tok, code = setup_vault()
    blob = v.to_blob()
    hl = len(ratchet.parse_fido_header(blob)["header"])
    for pos in range(hl):
        b = bytearray(blob)
        b[pos] ^= 0x01
        with pytest.raises(SigillumError):
            open_fido(bytes(b), tok)
        with pytest.raises(SigillumError):
            ratchet.Vault.open(bytes(b), PW, PIN, KF, code=code)


def test_body_flip_rejected():
    v, tok, code = setup_vault()
    blob = v.to_blob()
    for pos in (len(blob) - 1, len(blob) - 20, len(ratchet.parse_fido_header(blob)["header"]) + 3):
        b = bytearray(blob)
        b[pos] ^= 0x80
        with pytest.raises(SigillumError):
            open_fido(bytes(b), tok)


def test_slot_rules_enforced():
    v, tok, code = setup_vault()
    salt = v.new_prf_salt()
    toks = [SoftToken() for _ in range(5)]
    keys = [t.enroll(salt) for t in toks]
    with pytest.raises(SigillumError):
        v.protect(salt, keys, code, full(v))                       # 5 Keys
    with pytest.raises(SigillumError):
        v.protect(salt, [], code, full(v))                         # kein Key
    with pytest.raises(SigillumError):
        v.protect(salt, [keys[0], keys[0]], code, full(v))         # doppelt
    v.protect(salt, keys[:4], code, full(v))
    blob = v.to_blob()
    for t in toks[:4]:
        assert open_fido(blob, t).fido
    with pytest.raises(SigillumError):
        open_fido(blob, toks[4])


def _rebuild(h, slots):
    hdr = h["header"][:6] + h["salt"] + h["prf_salt"] + bytes([len(slots)])
    for sl in slots:
        hdr += bytes([sl["type"]]) + len(sl["meta"]).to_bytes(2, "big") + sl["meta"] + sl["nonce"] + sl["wrapped"]
    return hdr + h["nonce"] + h["ct"]


def test_slot_removal_or_duplication_rejected():
    v, tok, code = setup_vault()
    h = ratchet.parse_fido_header(v.to_blob())
    fido = [s for s in h["slots"] if s["type"] == ratchet.SLOT_DAILY]
    codes = [s for s in h["slots"] if s["type"] == 2]
    for slots in (fido, codes, fido + codes + codes, codes + fido):
        blob = _rebuild(h, slots)
        with pytest.raises(SigillumError):
            open_fido(blob, tok)
    assert open_fido(_rebuild(h, fido + codes), tok).fido          # Original-Reihenfolge geht


def test_downgrade_to_mode3_impossible():
    v, tok, code = setup_vault()
    blob = bytearray(v.to_blob())
    blob[3] = core.MODE_IDENTITY
    with pytest.raises(SigillumError):
        ratchet.Vault.open(bytes(blob), PW, PIN, KF)


def test_cred_id_length_limits():
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    salt = v.new_prf_salt()
    with pytest.raises(SigillumError):
        v.protect(salt, [(b"", bytes(32))], v.new_code(), full(v))
    with pytest.raises(SigillumError):
        v.protect(salt, [(b"x" * 1024, bytes(32))], v.new_code(), full(v))
    v.protect(salt, [(b"x" * 1023, bytes(32))], v.new_code(), full(v))
    assert ratchet.parse_fido_header(v.to_blob())["cred_ids"] == [b"x" * 1023]


def test_truncated_files_rejected():
    v, tok, code = setup_vault()
    blob = v.to_blob()
    for n in range(0, len(ratchet.parse_fido_header(blob)["header"]) + 20, 7):
        with pytest.raises(SigillumError):
            open_fido(blob[:n], tok)


# ------------------------------------------------------------------ Erneuern, Ersetzen, Ausschalten
def test_renewal_invalidates_old_code_and_old_body_key():
    v, tok, code = setup_vault()
    old_blob = v.to_blob()
    a = ratchet.Vault.open(old_blob, PW, PIN, KF, code=code)
    old_body = a._prot["body"]
    salt = a.new_prf_salt()
    new_code = a.new_code()
    a.protect(salt, [tok.derive(a.fido_cred_ids(), salt)], new_code, full(a))
    new_blob = a.to_blob()
    with pytest.raises(SigillumError):
        ratchet.Vault.open(new_blob, PW, PIN, KF, code=code)
    h = ratchet.parse_fido_header(new_blob)
    with pytest.raises(SigillumError):
        core._aead_decrypt(h["ct"], h["header"], h["nonce"], old_body)
    assert ratchet.Vault.open(new_blob, PW, PIN, KF, code=new_code).fido
    assert open_fido(new_blob, tok).fido


def test_replace_key_old_key_locked_out():
    v, tok, code = setup_vault()
    new_tok = SoftToken()
    salt = v.new_prf_salt()
    v.protect(salt, [new_tok.enroll(salt)], v.new_code(), full(v))
    blob = v.to_blob()
    with pytest.raises(SigillumError):
        open_fido(blob, tok)
    assert open_fido(blob, new_tok).fido


def test_unprotect_back_to_mode3():
    v, tok, code = setup_vault()
    v.unprotect(full(v))
    blob = v.to_blob()
    assert ratchet.file_mode(blob) == core.MODE_IDENTITY
    assert not ratchet.Vault.open(blob, PW, PIN, KF).fido


def test_clone_independent():
    v, tok, code = setup_vault()
    c = v.clone()
    c.unprotect(full(c))
    assert v.fido and not c.fido


def test_prf_salt_changes_secret():
    tok = SoftToken()
    s1, s2 = bytes(32), b"\x01" * 32
    cid, p1 = tok.enroll(s1)
    assert tok.derive([cid], s1)[1] == p1 != tok.derive([cid], s2)[1]


def test_wrong_fido_pin_counts_down():
    tok = SoftToken()
    v, tok, code = setup_vault(tok)
    blob = v.to_blob()
    tok.entered = "000000"
    for _ in range(8):
        with pytest.raises(SigillumError):
            open_fido(blob, tok)
    tok.entered = tok.pin
    with pytest.raises(SigillumError, match="gesperrt"):
        open_fido(blob, tok)
    assert ratchet.Vault.open(blob, PW, PIN, KF, code=code).opened_with_code


# ------------------------------------------------------------------ Notfall-Paket
def test_package_all_pairs():
    code_id, code = ratchet.Vault.new_code()
    parts = notfall.build(KF, code_id, code)
    assert len(parts) == 3 and all(p[:6] == b"SASHP3" and len(p) == 209 for p in parts)
    for pair in itertools.permutations(parts, 2):
        assert notfall.open_parts(list(pair)) == (KF, code_id, code)
    assert notfall.verify_all_pairs(parts, KF, code_id, code)
    with pytest.raises(ValueError):
        notfall.open_parts([parts[0]])


def test_package_and_keyfile_backup_not_mixed():
    code_id, code = ratchet.Vault.new_code()
    parts = notfall.build(KF, code_id, code)
    old = shamir.split(KF)
    with pytest.raises(ValueError):
        shamir.combine([parts[0], old[1]])
    with pytest.raises(ValueError):
        notfall.open_parts(old[:2])
    assert shamir.combine(old[:2]) == KF                  # altes Backup weiter gültig


def test_single_package_part_reveals_nothing_statistically():
    code_id, code = bytes(16), bytes(32)
    counts = [0] * 256
    for _ in range(8000):
        counts[notfall.build(KF, code_id, code)[0][13 + 80]] += 1      # mittleres Byte von y (< 2^1279-1)
    assert max(counts) < 3 * 8000 / 256 and min(counts) > 8000 / 256 / 3


def test_package_bad_parts():
    code_id, code = ratchet.Vault.new_code()
    parts = notfall.build(KF, code_id, code)
    with pytest.raises(ValueError):
        notfall.open_parts([parts[0], parts[0]])
    with pytest.raises(ValueError):
        notfall.open_parts([parts[0], notfall.build(KF, code_id, code)[1]])     # anderer Satz
    with pytest.raises(ValueError):
        notfall.open_parts([parts[0][:-1], parts[1]])


def test_package_unlocks_vault():
    v, tok, code = setup_vault()
    parts = notfall.build(KF, *code)
    kf, cid, c = notfall.open_parts(parts[1:])
    assert ratchet.Vault.open(v.to_blob(), PW, PIN, kf, code=(cid, c)).opened_with_code


# ------------------------------------------------------------------ Adapter python-fido2
def test_adapter_options_and_prf_parsing(monkeypatch):
    """Prüft, was an python-fido2 übergeben wird, und das Lesen beider Antwortformen."""
    from fido2.ctap2.extensions import AuthenticatorExtensionsPRFOutputs, AuthenticatorExtensionsPRFValues
    from fido2.webauthn import AuthenticationExtensionsClientOutputs
    seen = {}
    secret = b"\x42" * 32
    cid = b"\x11" * 40

    class FakeAuthData:
        def __init__(self, uv=True):
            self.uv = uv
            self.flags = 0x05                            # UP | UV, kein BE/BS (wie ein YubiKey)

        def is_user_verified(self):
            return self.uv

    class FakeClient:
        def make_credential(self, options):
            seen["mc"] = options
            ext = AuthenticationExtensionsClientOutputs({"prf": AuthenticatorExtensionsPRFOutputs(enabled=True)})
            att = type("A", (), {"auth_data": FakeAuthData()})()
            return type("R", (), {"raw_id": cid, "client_extension_results": ext,
                                  "response": type("X", (), {"attestation_object": att})()})()

        def get_assertion(self, options):
            seen["ga"] = options
            ext = AuthenticationExtensionsClientOutputs(
                {"prf": {"results": {"first": secret}}})          # Windows-Form (dict)
            resp = type("R", (), {"raw_id": cid, "client_extension_results": ext,
                                  "response": type("X", (), {"authenticator_data": FakeAuthData()})()})()
            return type("S", (), {"get_response": lambda self, i: resp})()

    tok = fidokey.Fido2Token()
    monkeypatch.setattr(tok, "_client", lambda: FakeClient())
    salt = b"\x07" * 32
    assert tok.enroll(salt) == (cid, secret)
    mc, ga = seen["mc"], seen["ga"]
    assert mc.rp.id == fidokey.RP_ID
    assert mc.authenticator_selection.user_verification == "required"
    assert mc.authenticator_selection.resident_key == "discouraged"
    assert mc.extensions["credentialProtectionPolicy"] == "userVerificationRequired"
    assert mc.extensions["enforceCredentialProtectionPolicy"] is True
    assert mc.extensions["prf"]["eval"]["first"] == salt
    assert ga.user_verification == "required" and ga.rp_id == fidokey.RP_ID
    assert [c.id for c in ga.allow_credentials] == [cid]
    assert ga.extensions["prf"]["eval"]["first"] == salt
    # R4-3 / R4-4: nur externer Sicherheitsschlüssel über USB, RP-ID nie auflösbar
    assert mc.authenticator_selection.authenticator_attachment == "cross-platform"
    assert list(mc.hints) == ["security-key"] and list(ga.hints) == ["security-key"]
    assert [list(c.transports) for c in ga.allow_credentials] == [["usb"]]
    assert fidokey.RP_ID.endswith(".invalid") and fidokey.ORIGIN == "https://" + fidokey.RP_ID
    # Objekt-Form (Fido2Client)
    ext = AuthenticationExtensionsClientOutputs({"prf": AuthenticatorExtensionsPRFOutputs(
        results=AuthenticatorExtensionsPRFValues(first=secret))})
    assert fidokey._prf_first(ext) == secret


def test_adapter_rejects_missing_uv_and_bad_prf(monkeypatch):
    from fido2.webauthn import AuthenticationExtensionsClientOutputs

    def client(uv, first, raw=b"\x11" * 40):
        class C:
            def get_assertion(self, options):
                ext = AuthenticationExtensionsClientOutputs({"prf": {"results": {"first": first}}} if first else {})
                ad = type("D", (), {"is_user_verified": lambda self: uv})()
                resp = type("R", (), {"raw_id": raw, "client_extension_results": ext,
                                      "response": type("X", (), {"authenticator_data": ad})()})()
                return type("S", (), {"get_response": lambda self, i: resp})()
        return C()

    tok = fidokey.Fido2Token()
    for uv, first, raw, msg in [(False, b"\x01" * 32, b"\x11" * 40, "PIN-Prüfung"),
                                (True, None, b"\x11" * 40, "kein gültiges"),
                                (True, b"\x01" * 31, b"\x11" * 40, "kein gültiges"),
                                (True, b"\x01" * 32, b"\x22" * 40, "fremden Zugang")]:
        monkeypatch.setattr(tok, "_client", lambda uv=uv, first=first, raw=raw: client(uv, first, raw))
        with pytest.raises(fidokey.FidoError, match=msg):
            tok.derive([b"\x11" * 40], bytes(32))


def test_adapter_error_mapping():
    from fido2.client import ClientError
    from fido2.ctap import CtapError
    e = ClientError(ClientError.ERR.BAD_REQUEST, CtapError(CtapError.ERR.PIN_INVALID))
    assert "PIN falsch" in str(fidokey._client_error(e))
    assert "nicht zu dieser" in str(fidokey._client_error(ClientError(ClientError.ERR.DEVICE_INELIGIBLE)))
    assert "Zeit" in str(fidokey._client_error(ClientError(ClientError.ERR.TIMEOUT)))



# ------------------------------------------------------------------ vierte Prüfrunde
def test_r4_5_forged_part_detected_and_honest_pair_used():
    code_id, code = ratchet.Vault.new_code()
    parts = notfall.build(KF, code_id, code)
    for pos in (14, 13 + 50, 13 + 159, 13 + 160 + 5):         # Anteil y (vorn, Mitte, hinten), Bindewert
        b = bytearray(parts[0][:-4])
        b[pos] ^= 0x5A
        forged = bytes(b) + shamir._chk(bytes(b))
        with pytest.raises((ValueError, SigillumError)):
            notfall.open_parts([forged, parts[1]])
        assert notfall.open_parts([forged, parts[1], parts[2]]) == (KF, code_id, code)
        assert notfall.open_parts([parts[2], forged, parts[1]]) == (KF, code_id, code)


def test_r4_5_old_package_format_rejected():
    code_id, code = ratchet.Vault.new_code()
    p = notfall.build(KF, code_id, code)
    for magic in (b"SASHR2", b"SASHR3"):                     # Formate vor Version 10
        old = magic + p[0][6:-4]
        old += shamir._chk(old)
        with pytest.raises(ValueError):
            notfall.open_parts([old, p[1]])


def test_r4_5_binding_reveals_nothing_about_single_part():
    code_id, code = ratchet.Vault.new_code()
    a, b = notfall.build(KF, code_id, code), notfall.build(KF, code_id, code)
    assert a[0][13 + 160:-4] != b[0][13 + 160:-4]             # Bindewert hängt am Satz, nicht nur am Geheimnis


def test_r4_2_recovery_flag_persisted_and_cleared():
    v, tok, code = setup_vault()
    a = ratchet.Vault.open(v.to_blob(), PW, PIN, KF, code=code)
    a.mark_recovery_used()
    b = open_fido(a.to_blob(), tok)
    assert b.recovery_pending
    salt = b.new_prf_salt()
    b.protect(salt, [tok.derive(b.fido_cred_ids(), salt)], b.new_code(), full(b))
    assert not open_fido(b.to_blob(), tok).recovery_pending
    b.mark_recovery_used()
    b.unprotect(full(b))
    assert not ratchet.Vault.open(b.to_blob(), PW, PIN, KF).recovery_pending


def test_r4_2_flag_validated():
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    v.state["recovery_pending"] = "ja"
    with pytest.raises(SigillumError):
        ratchet.Vault.open(v.to_blob(), PW, PIN, KF)


def test_r4_6_find_copies(tmp_path):
    v, tok, code = setup_vault()
    cur = tmp_path / "anna.said"
    cur.write_bytes(v.to_blob())
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "alt.said").write_bytes(v.to_blob())
    other = ratchet.Vault.create("Ben", PW, PIN, KF)
    (tmp_path / "ben.said").write_bytes(other.to_blob())
    (tmp_path / "kaputt.said").write_bytes(b"SA")
    (tmp_path / "nicht.txt").write_bytes(v.to_blob())
    hits = ratchet.find_copies([str(tmp_path)], v.salt, str(cur))
    assert hits == [str(tmp_path / "sub" / "alt.said")]


def test_r5_classify_copies(tmp_path):
    """Ältere Sicherung mit gleichem Schutz bleibt; Kopien ohne Key oder mit altem Code gelten als schwach."""
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    mode3 = v.to_blob()
    tok = SoftToken()
    salt = v.new_prf_salt()
    v.protect(salt, [tok.enroll(salt)], v.new_code(), full(v))
    same = v.to_blob()                                    # gleiche Hüllen, neuer Inhalt-Nonce
    old5 = same
    salt2 = v.new_prf_salt()
    v.protect(salt2, [tok.derive(v.fido_cred_ids(), salt2)], v.new_code(), full(v))
    same = v.to_blob()
    files = {"m3": mode3, "old5": old5, "same": same, "junk": b"SA\x02\x05" + bytes(20)}
    for k, b in files.items():
        (tmp_path / f"{k}.said").write_bytes(b)
    got = {k: ratchet.classify_copy(str(tmp_path / f"{k}.said"), v) for k in files}
    assert got == {"m3": "weak", "old5": "weak", "same": "same", "junk": "weak"}



# ------------------------------------------------------------------ sechste Prüfrunde
def test_r6_2_pin_cancel_not_reported_as_missing_pin():
    from fido2.client import ClientError, PinRequiredError
    from fido2.ctap import CtapError
    m = str(fidokey._client_error(PinRequiredError()))
    assert "abgebrochen" in m and "NICHT zurücksetzen" in m and "keine FIDO2-PIN gesetzt" not in m
    m = str(fidokey._client_error(ClientError(ClientError.ERR.BAD_REQUEST, CtapError(CtapError.ERR.PIN_NOT_SET))))
    assert "keine FIDO2-PIN gesetzt" in m


def test_adapter_rejects_synced_passkeys(monkeypatch):
    """Befund R12-N3: synchronisierbare Passkeys (BE/BS gesetzt) oder Handy (hybrid) werden abgelehnt."""
    from fido2.ctap2.extensions import AuthenticatorExtensionsPRFOutputs
    from fido2.webauthn import AuthenticationExtensionsClientOutputs
    cid, secret = b"\x11" * 40, b"\x42" * 32

    def client(flags_mc, flags_ga, transports=("usb",)):
        class AD:
            def __init__(self, f):
                self.flags = f

            def is_user_verified(self):
                return True

        class C:
            def make_credential(self, options):
                ext = AuthenticationExtensionsClientOutputs({"prf": AuthenticatorExtensionsPRFOutputs(enabled=True)})
                att = type("A", (), {"auth_data": AD(flags_mc)})()
                return type("R", (), {"raw_id": cid, "client_extension_results": ext,
                                      "response": type("X", (), {"attestation_object": att,
                                                                 "transports": list(transports)})()})()

            def get_assertion(self, options):
                ext = AuthenticationExtensionsClientOutputs({"prf": {"results": {"first": secret}}})
                resp = type("R", (), {"raw_id": cid, "client_extension_results": ext,
                                      "response": type("X", (), {"authenticator_data": AD(flags_ga)})()})()
                return type("S", (), {"get_response": lambda self, i: resp})()
        return C()

    salt = b"\x07" * 32
    for f_mc, f_ga, tr in [(0x05 | 0x08, 0x05, ("usb",)), (0x05 | 0x18, 0x05, ("usb",)), (0x05 | 0x10, 0x05, ("usb",)),
                           (0x05, 0x05 | 0x08, ("usb",))]:
        tok = fidokey.Fido2Token()
        monkeypatch.setattr(tok, "_client", lambda f=f_mc, g=f_ga, t=tr: client(f, g, t))
        with pytest.raises(fidokey.FidoError):
            tok.enroll(salt)
    tok = fidokey.Fido2Token()
    monkeypatch.setattr(tok, "_client", lambda: client(0x05, 0x05))
    assert tok.enroll(salt) == (cid, secret)
