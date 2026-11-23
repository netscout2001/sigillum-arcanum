"""Identitätsdatei (Vault) und Kontakt-Nachrichten mit Schlüsselwechsel (seit 11.2: Vorrat an Einmal-Schlüsseln).

Prinzip
  * Die Identität (ECDSA-brainpoolP512r1 + ML-DSA-87, hybrid) bleibt stabil; ihr Fingerabdruck wird einmal verifiziert.
  * Jede Nachricht enthält – verschlüsselt und signiert – einen NEUEN Empfangsschlüssel (Hybrid-KEM ML-KEM-1024 + ECDH-brainpoolP512r1).
    Der Partner verschlüsselt seine nächste Nachricht an diesen Schlüssel.
  * Benutzt der Partner einen neueren Schlüssel, werden alle älteren eigenen SOFORT gelöscht.
  * Im Geheimtext stehen weder Absender noch Empfänger noch Schlüsselnummer (Befund M2).
    Der Empfänger probiert seine Schlüssel durch.
  * Die Signaturen liegen INNERHALB der Verschlüsselung und decken den Empfänger mit ab (Befund M3):
    Dritte können die Urheberschaft nicht prüfen, und der Empfänger kann eine Nachricht nicht
    unbemerkt an jemand anderen weiterleiten, als wäre sie an diesen gerichtet.
  * Kontakte, Verifizierung, Schlüsselstand und benutzte Zufallsblätter liegen verschlüsselt in der
    Identitätsdatei (Befunde M1, L7).
"""
import copy
import hashlib
import hmac
import json
import secrets
import struct
import time
import unicodedata

from . import core
from .core import SigillumError
from .i18n import _

MODE = core.MODE_CONTACT_POOL          # gesendet wird nur noch Modus 6; Modus 4 (bis 11.1) wird weiter gelesen
MODES = (core.MODE_CONTACT, core.MODE_CONTACT_POOL)
SIG_CONTEXT = b"SIGILLUM-ARCANUM-v3-sig"
BASE_ID = b"\x00" * 8
MAX_OPEN_KEYS = 1000                   # Obergrenze unbeantworteter eigener Schlüssel je Kontakt
POOL = 5                               # Befund R12-N1: je Nachricht 5 neue Empfangsschlüssel – 4 Einmal-Schlüssel und
                                       # 1 Rückfallschlüssel (für weitere Nachrichten, bis eine Antwort kommt)
KEY_LEN = 8 + core.HKEM_PK             # id | Hybrid-KEM-Schlüssel
ANN_LEN = 8 + KEY_LEN                  # Modus 4: seq | id | Schlüssel
ANN_LEN_POOL = 8 + 1 + POOL * KEY_LEN  # Modus 6: seq | Anzahl | Anzahl × (id | Schlüssel)
HDR_LEN = 4 + core.HKEM_CT + core.NONCE_LEN
PLAIN_FIXED = 32 + core.SIG_LEN + ANN_LEN
PLAIN_FIXED_POOL = 32 + core.SIG_LEN + ANN_LEN_POOL
STATE_MAGIC = b"SAPRV5"
MAX_VAULT = 64 * 1024 * 1024
METHODS = ("persönlich", "Video mit Rückfrage")    # gespeicherte Kennungen – Anzeige übersetzt die GUI
GAP_SHOW = 20                       # so viele fehlende Nummern werden höchstens einzeln genannt
MAX_SEQ = 2 ** 63
MAX_SEEN = 2000                     # gemerkte Kennungen geöffneter Nachrichten je Kontakt (Befund R3-1)
MAX_SKEW = 600                      # Zeitstempel zählen höchstens 10 Minuten über die Empfangszeit hinaus


# ================================================================ Identitätsdatei

def new_state() -> dict:
    return {"v": 4, "contacts": {}, "book": {}, "sheets": {}, "sheets_opened": {}, "seen": {}, "partners": {}}


_HEX = set("0123456789abcdef")


def _is_hex(x, n=None) -> bool:
    return isinstance(x, str) and (n is None or len(x) == n) and len(x) % 2 == 0 and set(x) <= _HEX


def _migrate(state: dict) -> dict:
    """Zustand der Identität streng prüfen (v11: Zustand v4 mit Prüfwerten "chk" und Partner-Einträgen)."""
    if state.get("v") != 4:
        raise ValueError
    for k in ("contacts", "book", "sheets", "sheets_opened", "seen", "partners"):
        if not isinstance(state.get(k), dict):
            raise ValueError
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in state["sheets"].items()):
        raise ValueError
    if not all(isinstance(k, str) and type(v) is int and v >= 0 for k, v in state["sheets_opened"].items()):
        raise ValueError
    for rec in state["seen"].values():
        if (not isinstance(rec, dict) or not isinstance(rec.get("ids"), list) or type(rec.get("ts")) is not int
                or not all(isinstance(x, str) for x in rec["ids"])):
            raise ValueError
    if not isinstance(state.get("recovery_pending", False), bool):
        raise ValueError
    if "spent" in state and (not isinstance(state["spent"], list) or len(state["spent"]) > MAX_SEEN
                             or not all(_is_hex(x, 32) for x in state["spent"])):
        raise ValueError
    if "gen" in state and (type(state["gen"]) is not int or not 0 <= state["gen"] < 2 ** 62):
        raise ValueError                                  # Befund R12-N4: Schreib-Generation (fehlt vor 11.2 = 0)
    chk = state.get("chk")
    # "d" (Prüfwert für A2) seit 11.1; Identitäten aus 11.0 bekommen ihn beim nächsten Alltags-Entsperren bzw. bei der
    # nächsten Schritt-Bestätigung (beides erst, nachdem A2 bewiesen ist) – keine Selbstaussperrung.
    if (not isinstance(chk, dict) or set(chk) - {"d"} != {"a", "pw_salt", "pw"} or not _is_hex(chk["a"], 64)
            or ("d" in chk and not _is_hex(chk["d"], 64)) or not _is_hex(chk["pw_salt"], 32)
            or not _is_hex(chk["pw"], 64)):
        raise ValueError
    if len(state["partners"]) > MAX_PARTNERS:
        raise ValueError
    for pid, p in state["partners"].items():
        if (not _is_hex(pid, 16) or not isinstance(p, dict)
                or set(p) != {"name", "kf", "pw", "pin", "created", "last_used"}
                or not all(isinstance(p[k], str) for k in ("name", "kf", "pw", "pin"))
                or not _is_hex(p["kf"], 88) or type(p["created"]) is not int or type(p["last_used"]) is not int
                or p["created"] < 0 or p["last_used"] < 0):
            raise ValueError
        # Befund R11-9a: dieselben Regeln wie beim Anlegen (add_partner) – SigillumError wird unten abgefangen
        core.read_keyfile(bytes.fromhex(p["kf"]))
        if core._check_name(p["name"]) != p["name"]:
            raise ValueError
        core.check_passphrase_stored(p["pw"])
        core.check_pin(p["pin"])
        if (p["pw"] != core.canonical_passphrase(p["pw"]) or p["pin"] != unicodedata.normalize("NFC", p["pin"]).strip()
                or hmac.compare_digest(_pw_check(bytes.fromhex(chk["pw_salt"]), p["pw"]), chk["pw"])):
            raise ValueError                                  # H1: nie die Passphrase der Identität
    return state


# ---------------------------------------------------------------- Modus 5: Hüllen für YubiKey / Notfall-Code
# v11: Die YubiKey-Hülle ist eine ALLTAGS-Hülle (Typ 3): KEK aus A2 = Argon2id(PIN, Schlüsseldatei, Zweck "daily")
# und dem YubiKey-Geheimnis – OHNE Passphrase. Die Notfall-Hülle (Typ 2) braucht A (mit Passphrase) + Notfall-Code.
# Typ 1 (YubiKey-Hülle bis Version 10.1, mit Passphrase) wird nicht mehr angenommen.
SLOT_LEGACY_FIDO, SLOT_CODE, SLOT_DAILY = 1, 2, 3
MAX_FIDO_SLOTS = 4
CODE_ID_LEN, CODE_LEN, PRF_SALT_LEN = 16, 32, 32
WRAP_LEN = 32 + 16
MAX_PARTNERS = 64


def _slot_kek(base_key: bytes, secret: bytes, typ: int, meta: bytes) -> bytes:
    info = b"SIGILLUM-v3-slot" + bytes([typ]) + core.h3(b"SIGILLUM-v3-slot-meta", meta)
    return core.hkdf(base_key + secret, info)


def _prefix() -> bytes:
    return core.MAGIC + bytes([core.VERSION, core.MODE_IDENTITY_FIDO, core.KDF_OPS, core.KDF_MEMLOG])


def _slot_aad(prefix: bytes, salt: bytes, prf_salt: bytes, typ: int, meta: bytes) -> bytes:
    return prefix + salt + prf_salt + bytes([typ]) + meta


def _check_slots(slots: list):
    if any(s["type"] == SLOT_LEGACY_FIDO for s in slots):
        raise SigillumError(_("Identitätsdatei aus einer älteren App-Version (YubiKey-Format vor Version 11) – "
                              "bitte die Identität mit Version 11 neu erzeugen."))
    fido = [s for s in slots if s["type"] == SLOT_DAILY]
    code = [s for s in slots if s["type"] == SLOT_CODE]
    if len(code) != 1 or not 1 <= len(fido) <= MAX_FIDO_SLOTS or len(fido) + len(code) != len(slots):
        raise SigillumError(_("Identitätsdatei: ungültige YubiKey-/Notfall-Einträge."))
    if any(not 1 <= len(s["meta"]) <= 1023 for s in fido) or len(code[0]["meta"]) != CODE_ID_LEN:
        raise SigillumError(_("Identitätsdatei: ungültige YubiKey-/Notfall-Einträge."))
    if len({s["meta"] for s in fido}) != len(fido):
        raise SigillumError(_("Identitätsdatei: doppelter YubiKey-Eintrag."))


def _fido_header(salt: bytes, prf_salt: bytes, slots: list, nonce: bytes) -> bytes:
    h = _prefix() + salt + prf_salt + bytes([len(slots)])
    for sl in slots:
        h += bytes([sl["type"]]) + struct.pack(">H", len(sl["meta"])) + sl["meta"] + sl["nonce"] + sl["wrapped"]
    return h + nonce


def parse_fido_header(blob: bytes) -> dict:
    """Kopf einer Modus-5-Datei streng lesen (ohne Schlüssel). Wirft SigillumError bei jeder Abweichung."""
    bad = SigillumError(_("Identitätsdatei beschädigt."))
    if core.message_mode(blob) != core.MODE_IDENTITY_FIDO:
        raise SigillumError(_("Keine Identitätsdatei mit YubiKey."))
    if len(blob) < 6:                                  # Befund R8-N1: zu kurze Datei sauber ablehnen
        raise bad
    ops, memlog = blob[4], blob[5]
    if (ops, memlog) not in core.ALLOWED_KDF:
        raise SigillumError(_("Unzulässige Schlüsselableitungs-Parameter in der Datei – abgelehnt."))
    p = 6
    salt, prf_salt = blob[p:p + core.SALT_LEN], blob[p + core.SALT_LEN:p + core.SALT_LEN + PRF_SALT_LEN]
    p += core.SALT_LEN + PRF_SALT_LEN
    if len(blob) < p + 1:
        raise bad
    n = blob[p]
    p += 1
    if not 2 <= n <= 1 + MAX_FIDO_SLOTS:
        raise bad
    slots = []
    for _u in range(n):
        if len(blob) < p + 3:
            raise bad
        typ = blob[p]
        (mlen,) = struct.unpack(">H", blob[p + 1:p + 3])
        p += 3
        if typ not in (SLOT_LEGACY_FIDO, SLOT_DAILY, SLOT_CODE) or len(blob) < p + mlen + core.NONCE_LEN + WRAP_LEN:
            raise bad
        meta = blob[p:p + mlen]
        p += mlen
        nonce = blob[p:p + core.NONCE_LEN]
        p += core.NONCE_LEN
        wrapped = blob[p:p + WRAP_LEN]
        p += WRAP_LEN
        slots.append({"type": typ, "meta": meta, "nonce": nonce, "wrapped": wrapped})
    _check_slots(slots)
    if len(blob) < p + core.NONCE_LEN + 16:
        raise bad
    nonce = blob[p:p + core.NONCE_LEN]
    p += core.NONCE_LEN
    return {"header": blob[:p], "ops": ops, "memlog": memlog, "salt": salt, "prf_salt": prf_salt,
            "slots": slots, "nonce": nonce, "ct": blob[p:],
            "cred_ids": [s["meta"] for s in slots if s["type"] == SLOT_DAILY],
            "code_id": next(s["meta"] for s in slots if s["type"] == SLOT_CODE)}


def file_mode(blob: bytes) -> int:
    """3 = Identität ohne YubiKey, 5 = mit YubiKey."""
    m = core.message_mode(blob)
    if m not in (core.MODE_IDENTITY, core.MODE_IDENTITY_FIDO):
        raise SigillumError(_("Das ist keine Identitätsdatei."))
    return m


def _parse_raw(raw: bytes):
    try:
        if raw[:6] != STATE_MAGIC:
            raise ValueError
        (n,) = struct.unpack(">I", raw[6:10])
        name = raw[10:10 + n].decode("utf-8")
        p = 10 + n
        secret = raw[p:p + core.Identity.SECRET_LEN]
        p += core.Identity.SECRET_LEN
        (m,) = struct.unpack(">I", raw[p:p + 4])
        if p + 4 + m != len(raw):
            raise ValueError
        state = json.loads(raw[p + 4:].decode("utf-8"))
        if not isinstance(state, dict):
            raise ValueError
        state = _migrate(state)
        ident = core.Identity.from_secret(name, secret)
    except (ValueError, struct.error, UnicodeDecodeError, AttributeError, SigillumError):
        raise SigillumError(_("Identitätsdatei beschädigt oder aus einer älteren Version.")) from None
    return ident, state


def _a_check(a_key: bytes) -> str:
    return core.h3(b"SIGILLUM-v11-A-CHECK", a_key).hex()


def _d_check(d_key: bytes) -> str:
    """Befund R11-H-c: Prüfwert für A2 (Alltags-Schlüssel), damit nie eine unbrauchbare Alltags-Hülle entsteht."""
    return core.h3(b"SIGILLUM-v11-A2-CHECK", d_key).hex()


def _pw_check(pw_salt: bytes, passphrase: str) -> str:
    # Diceware >= 77,5 Bit: auch ein schneller Hash ist nicht durchprobierbar; liegt zudem nur VERSCHLÜSSELT im Inhalt.
    return hmac.new(pw_salt, core.canonical_passphrase(passphrase).encode("utf-8"), hashlib.sha256).hexdigest()


class Vault:
    """Geöffnete Identitätsdatei: Identität, Kontaktbuch, Partner, Schlüsselstand.

    Modus 3: Inhalt mit A = Argon2id(Passphrase, PIN, Schlüsseldatei) verschlüsselt.
    Modus 5: Inhalt mit Zufallsschlüssel M; M liegt in Hüllen:
             Alltags-Hülle je YubiKey (A2 = Argon2id(PIN, Schlüsseldatei, "daily") + YubiKey-Geheimnis),
             Notfall-Hülle (A + Notfall-Code). Im Alltag wird die Passphrase NICHT gebraucht.
    Der Inhalt enthält Prüfwerte: h3(A) (zum Nachprüfen der Passphrase vor sicherheitskritischen Änderungen) und
    HMAC(pw_salt, Passphrase) (Befund H1: gemeinsame Passphrase darf nicht die der Identität sein)."""

    def __init__(self, identity: core.Identity, state: dict, key, dkey, salt: bytes, kf_digest: str,
                 prot: dict | None = None):
        self.identity, self.state = identity, state
        self._key, self._dkey, self._salt = key, dkey, salt      # _key = A (oder None im Alltag), _dkey = A2
        self.kf_digest = kf_digest            # nicht geheim: erkennt Wiederverwendung der Schlüsseldatei (H1)
        self._prot = prot                     # None (Modus 3) oder {"body", "prf_salt", "slots", "via"}

    @classmethod
    def create(cls, name, passphrase, pin, keyfile):
        core.check_passphrase(passphrase)
        core.check_pin_new(pin)                               # Befund R12-N2
        salt = secrets.token_bytes(core.SALT_LEN)
        key = core.derive_key(passphrase, pin, keyfile, salt, core.PURPOSE_IDENTITY)
        dkey = core.derive_daily_key(pin, keyfile, salt)
        state = new_state()
        pw_salt = secrets.token_bytes(16)
        state["chk"] = {"a": _a_check(key), "d": _d_check(dkey), "pw_salt": pw_salt.hex(),
                        "pw": _pw_check(pw_salt, passphrase)}
        return cls(core.Identity.generate(name), state, key, None, salt, core.keyfile_digest(keyfile))

    @classmethod
    def open(cls, blob: bytes, passphrase, pin, keyfile, prf_fn=None, code=None):
        """Modus 3: Passphrase + PIN + Schlüsseldatei. Modus 5 Alltag: prf_fn(cred_ids, prf_salt) -> (cred_id, prf)
        + PIN + Schlüsseldatei (Passphrase wird ignoriert). Modus 5 Notfall: code = (code_id, code) + Passphrase."""
        if len(blob) > MAX_VAULT:
            raise SigillumError(_("Identitätsdatei zu groß."))
        kf_digest = core.keyfile_digest(keyfile)
        if file_mode(blob) == core.MODE_IDENTITY:
            header, ops, memlog, salt, nonce, ct = core._parse_shared_header(blob, core.MODE_IDENTITY)
            key = core.derive_key(passphrase, pin, keyfile, salt, core.PURPOSE_IDENTITY, ops, memlog)
            ident, state = _parse_raw(core._aead_decrypt(ct, header, nonce, key))
            if not hmac.compare_digest(state["chk"]["a"], _a_check(key)):
                raise SigillumError(_("Identitätsdatei beschädigt (Prüfwert)."))
            return cls(ident, state, key, None, salt, kf_digest)

        h = parse_fido_header(blob)
        if code is not None:
            code_id, code_val = code
            if not hmac.compare_digest(code_id, h["code_id"]):
                raise SigillumError(_("Dieses Notfall-Paket gehört nicht zu dieser Identitätsdatei (oder ist "
                                      "veraltet – es wurde inzwischen erneuert)."))
            if not passphrase:
                raise SigillumError(_("Für das Notfall-Paket werden Passphrase und PIN der Identität gebraucht."))
            key = core.derive_key(passphrase, pin, keyfile, h["salt"], core.PURPOSE_IDENTITY, h["ops"], h["memlog"])
            dkey = None
            slot, secret, via, base = next(s for s in h["slots"] if s["type"] == SLOT_CODE), code_val, "code", key
        elif prf_fn is not None:
            key = None
            dkey = core.derive_daily_key(pin, keyfile, h["salt"], h["ops"], h["memlog"])
            cred_id, prf = prf_fn(h["cred_ids"], h["prf_salt"])
            slot = next((s for s in h["slots"] if s["type"] == SLOT_DAILY and s["meta"] == cred_id), None)
            if slot is None:
                raise SigillumError(_("Dieser YubiKey gehört nicht zu dieser Identität."))
            secret, via, base = prf, "fido", dkey
        else:
            raise SigillumError(_("Diese Identität ist mit einem YubiKey geschützt."))
        if len(secret) != 32:
            raise SigillumError(_("Entsperren fehlgeschlagen."))
        try:
            body = core._aead_decrypt(slot["wrapped"], _slot_aad(h["header"][:6], h["salt"], h["prf_salt"], slot["type"],
                                                                 slot["meta"]),
                                      slot["nonce"], _slot_kek(base, secret, slot["type"], slot["meta"]))
        except SigillumError:
            raise SigillumError(_("Entsperren fehlgeschlagen: Passphrase, PIN, Schlüsseldatei oder Notfall-Code "
                                  "passen nicht zu dieser Identität.") if via == "code" else
                                _("Entsperren fehlgeschlagen: PIN, Schlüsseldatei oder YubiKey passen nicht zu dieser "
                                  "Identität.")) from None
        ident, state = _parse_raw(core._aead_decrypt(h["ct"], h["header"], h["nonce"], body))
        if key is not None and not hmac.compare_digest(state["chk"]["a"], _a_check(key)):
            raise SigillumError(_("Identitätsdatei beschädigt (Prüfwert)."))
        if dkey is not None:
            if "d" not in state["chk"]:
                state["chk"]["d"] = _d_check(dkey)      # 11.0 -> 11.1: A2 ist durch die geöffnete Alltags-Hülle bewiesen
            elif not hmac.compare_digest(state["chk"]["d"], _d_check(dkey)):
                raise SigillumError(_("Identitätsdatei beschädigt (Prüfwert)."))
        prot = {"body": body, "prf_salt": h["prf_salt"], "slots": h["slots"], "via": via}
        return cls(ident, state, key, dkey, h["salt"], kf_digest, prot=prot)

    @property
    def gen(self) -> int:
        """Befund R12-N4: zählt jedes Schreiben der Datei mit (verschlüsselt und authentisiert im Inhalt)."""
        return self.state.get("gen", 0)

    def to_blob(self) -> bytes:
        self.state["gen"] = self.gen + 1                               # jede geschriebene Fassung ist neuer
        name = self.identity.name.encode("utf-8")
        st = json.dumps(self.state, separators=(",", ":"), sort_keys=True).encode("utf-8")
        raw = STATE_MAGIC + core._lp(name) + self.identity.secret_bytes() + core._lp(st)
        nonce = secrets.token_bytes(core.NONCE_LEN)                    # neue Nonce bei jedem Schreiben
        if self._prot is None:
            if self._key is None:
                raise SigillumError(_("Interner Fehler: Schlüssel der Identität fehlt."))
            header = core._shared_header(core.MODE_IDENTITY, core.KDF_OPS, core.KDF_MEMLOG, self._salt, nonce)
            return header + core._aead_encrypt(raw, header, nonce, self._key)
        header = _fido_header(self._salt, self._prot["prf_salt"], self._prot["slots"], nonce)
        return header + core._aead_encrypt(raw, header, nonce, self._prot["body"])

    def clone(self) -> "Vault":
        """Arbeitskopie: Änderungen werden erst übernommen, wenn sie gespeichert sind."""
        prot = None if self._prot is None else dict(self._prot, slots=list(self._prot["slots"]))
        v = Vault(self.identity, copy.deepcopy(self.state), self._key, self._dkey, self._salt, self.kf_digest, prot)
        v._hk_cache = self.__dict__.setdefault("_hk_cache", {})        # Schlüssel-Objekte teilen (nur Arbeitsspeicher)
        return v

    # ---------------------------------------------------------- Prüfwerte / Nachweis der vollen Faktoren
    def same_passphrase(self, passphrase: str) -> bool:
        c = self.state["chk"]
        return hmac.compare_digest(_pw_check(bytes.fromhex(c["pw_salt"]), passphrase), c["pw"])

    def full_keys(self, passphrase: str, pin: str, keyfile: bytes) -> tuple[bytes, bytes]:
        """Nachweis aller Faktoren vor sicherheitskritischen Änderungen (YubiKey ein/aus/ersetzen, Notfall-Paket):
        liefert (A, A2) – nur wenn Passphrase, PIN und Schlüsseldatei genau zu DIESER Identität passen."""
        if core.keyfile_digest(keyfile) != self.kf_digest:
            raise SigillumError(_("Die Schlüsseldatei gehört nicht zu dieser Identität."))
        a = core.derive_key(passphrase, pin, keyfile, self._salt, core.PURPOSE_IDENTITY)
        if not hmac.compare_digest(_a_check(a), self.state["chk"]["a"]):
            raise SigillumError(_("Passphrase oder PIN passen nicht zu dieser Identität – nichts geändert."))
        d = core.derive_daily_key(pin, keyfile, self._salt)
        if "d" not in self.state["chk"]:
            self.state["chk"]["d"] = _d_check(d)       # 11.0 -> 11.1: PIN und Schlüsseldatei sind über A bewiesen
        if not hmac.compare_digest(_d_check(d), self.state["chk"]["d"]):
            raise SigillumError(_("Identitätsdatei beschädigt (Prüfwert) – nichts geändert."))
        return a, d

    # ---------------------------------------------------------- YubiKey-Schutz (Modus 5)
    @property
    def salt(self) -> bytes:
        """Argon2-Salz (offen im Dateikopf; bleibt über alle Versionen der Datei gleich)."""
        return self._salt

    @property
    def fido(self) -> bool:
        return self._prot is not None

    @property
    def opened_with_code(self) -> bool:
        return self._prot is not None and self._prot["via"] == "code"

    def fido_cred_ids(self) -> list:
        return [] if self._prot is None else [s["meta"] for s in self._prot["slots"] if s["type"] == SLOT_DAILY]

    def code_id(self):
        return None if self._prot is None else next(s["meta"] for s in self._prot["slots"] if s["type"] == SLOT_CODE)

    @staticmethod
    def new_prf_salt() -> bytes:
        return secrets.token_bytes(PRF_SALT_LEN)

    @staticmethod
    def new_code() -> tuple[bytes, bytes]:
        return secrets.token_bytes(CODE_ID_LEN), secrets.token_bytes(CODE_LEN)

    def protect(self, prf_salt: bytes, keys: list, code: tuple[bytes, bytes], full: tuple[bytes, bytes]):
        """Neue Hüllen: keys = [(cred_id, prf)] – PRF-Geheimnisse ZU DIESEM prf_salt; code = (code_id, code);
        full = (A, A2) aus full_keys(). Würfelt den Dateischlüssel M neu, damit alte Hüllen nichts mehr öffnen."""
        a_key, d_key = full
        if (len(prf_salt) != PRF_SALT_LEN or len(a_key) != 32 or len(d_key) != 32
                or not hmac.compare_digest(_a_check(a_key), self.state["chk"]["a"])
                or not hmac.compare_digest(_d_check(d_key), self.state["chk"].get("d", ""))):  # Befund R11-H-c
            raise SigillumError(_("Interner Fehler: Schlüssel oder PRF-Wert ungültig."))
        code_id, code_val = code
        if len(code_id) != CODE_ID_LEN or len(code_val) != CODE_LEN:
            raise SigillumError(_("Interner Fehler: Notfall-Code ungültig."))
        body = secrets.token_bytes(32)
        slots = []
        for typ, meta, secret, base in ([(SLOT_DAILY, c, p, d_key) for c, p in keys]
                                        + [(SLOT_CODE, code_id, code_val, a_key)]):
            if len(secret) != 32:
                raise SigillumError(_("Interner Fehler: Geheimnis ungültig."))
            nonce = secrets.token_bytes(core.NONCE_LEN)
            wrapped = core._aead_encrypt(body, _slot_aad(_prefix(), self._salt, prf_salt, typ, meta), nonce,
                                         _slot_kek(base, secret, typ, meta))
            slots.append({"type": typ, "meta": meta, "nonce": nonce, "wrapped": wrapped})
        _check_slots(slots)
        self._prot = {"body": body, "prf_salt": prf_salt, "slots": slots, "via": "setup"}
        self._key, self._dkey = a_key, d_key
        self.state.pop("recovery_pending", None)

    def unprotect(self, full: tuple[bytes, bytes]):
        """YubiKey ausschalten: zurück zu Modus 3 (Passphrase, PIN, Schlüsseldatei) – braucht A aus full_keys()."""
        a_key = full[0]
        if len(a_key) != 32 or not hmac.compare_digest(_a_check(a_key), self.state["chk"]["a"]):
            raise SigillumError(_("Interner Fehler: Schlüssel ungültig."))
        self._key, self._dkey, self._prot = a_key, None, None
        self.state.pop("recovery_pending", None)

    @property
    def recovery_pending(self) -> bool:
        """Befund R4-2: Notfall-Code wurde benutzt, aber noch nicht erneuert (in der Datei vermerkt)."""
        return bool(self.state.get("recovery_pending"))

    def mark_recovery_used(self):
        self.state["recovery_pending"] = True

    # ---------------------------------------------------------- Sitzung versiegeln (Schnell-Entsperren, v11)
    def session_bytes(self) -> bytes:
        """Alles Nötige, um diese geöffnete Identität ohne Datei wiederherzustellen (nur im Arbeitsspeicher)."""
        prot = None
        if self._prot is not None:
            prot = {"body": self._prot["body"].hex(), "prf_salt": self._prot["prf_salt"].hex(), "via": self._prot["via"],
                    "slots": [{"type": s["type"], "meta": s["meta"].hex(), "nonce": s["nonce"].hex(),
                               "wrapped": s["wrapped"].hex()} for s in self._prot["slots"]]}
        d = {"name": self.identity.name, "secret": self.identity.secret_bytes().hex(), "state": self.state,
             "key": self._key.hex() if self._key else None, "dkey": self._dkey.hex() if self._dkey else None,
             "salt": self._salt.hex(), "kf": self.kf_digest, "prot": prot}
        return json.dumps(d, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_session(cls, b: bytes) -> "Vault":
        try:
            d = json.loads(b.decode("utf-8"))
            prot = d["prot"]
            if prot is not None:
                prot = {"body": bytes.fromhex(prot["body"]), "prf_salt": bytes.fromhex(prot["prf_salt"]),
                        "via": prot["via"],
                        "slots": [{"type": s["type"], "meta": bytes.fromhex(s["meta"]), "nonce": bytes.fromhex(s["nonce"]),
                                   "wrapped": bytes.fromhex(s["wrapped"])} for s in prot["slots"]]}
                _check_slots(prot["slots"])
            state = _migrate(d["state"])
            ident = core.Identity.from_secret(d["name"], bytes.fromhex(d["secret"]))
            key = bytes.fromhex(d["key"]) if d["key"] else None
            dkey = bytes.fromhex(d["dkey"]) if d["dkey"] else None
            salt = bytes.fromhex(d["salt"])
            # Befund R11-H-d: Längen prüfen (Schlüssel 32 Byte, Salz wie im Dateikopf)
            if any(k is not None and len(k) != 32 for k in (key, dkey)) or len(salt) != core.SALT_LEN \
                    or not isinstance(d["kf"], str) or (prot is None and key is None):
                raise ValueError
            return cls(ident, state, key, dkey, salt, d["kf"], prot)
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
            raise SigillumError(_("Gesperrte Sitzung beschädigt.")) from None

    # ---------------------------------------------------------- Kontaktbuch (Befund M1)
    def contacts(self) -> list:
        out = []
        for fp, e in sorted(self.state["book"].items(), key=lambda kv: (kv[1]["name"].casefold(), kv[0])):
            out.append((core.Contact.from_bytes(bytes.fromhex(e["pub"])), e["verified"], e.get("method")))
        return out

    def contact(self, fp: str):
        e = self.state["book"].get(fp)
        if e is None:
            return None, False
        return core.Contact.from_bytes(bytes.fromhex(e["pub"])), e["verified"]

    def add_contact(self, c: core.Contact) -> list:
        """Fügt hinzu (unverifiziert). Gibt gleichnamige andere Kontakte zurück (Warnung vor Doppelgängern)."""
        if c.fp() == self.identity.public().fp():
            raise SigillumError(_("Das ist deine eigene Identität."))
        sk = core.name_skeleton(c.name)
        same = [x for x, _u, _u in self.contacts() if core.name_skeleton(x.name) == sk and x.fp() != c.fp()]
        self.state["book"].setdefault(c.fp(), {"name": c.name, "pub": c.to_bytes().hex(), "verified": False,
                                               "method": None, "added": int(time.time())})
        return same

    def verify_contact(self, fp: str, typed: str, method: str):
        """Nur wenn der vom Partner vorgelesene Fingerabdruck vollständig übereinstimmt (Befund M5)."""
        c, _u = self.contact(fp)
        if c is None:
            raise SigillumError(_("Kontakt nicht gefunden."))
        if method not in METHODS:
            raise SigillumError(_("Bitte persönlich oder per Video mit Rückfrage vergleichen."))
        expected = core.normalize_fingerprint(c.fingerprint())
        if not hmac.compare_digest(core.normalize_fingerprint(typed).encode(), expected.encode()):
            raise SigillumError(_("Fingerabdruck stimmt NICHT überein. Kontakt bleibt unverifiziert. Nicht verwenden!"))
        e = self.state["book"][fp]
        e.update({"verified": True, "method": method, "verified_at": int(time.time())})

    def remove_contact(self, fp: str):
        self.state["book"].pop(fp, None)
        cs = self.state["contacts"].pop(fp, None)
        if cs:                                       # Register bleibt: Wiederholungen nach erneutem Import erkennen
            rec = self.state["seen"].setdefault(fp, {"ids": [], "ts": 0})
            rec["ts"] = max(rec["ts"], int(cs.get("last_ts", 0)))

    # ---------------------------------------------------------- Partner mit gemeinsamem Schlüssel (v11, Variante C)
    def partners(self) -> list:
        """[(pid, name, angelegt, zuletzt benutzt)] – ohne Geheimnisse, nach Name sortiert."""
        return sorted(((pid, p["name"], p["created"], p["last_used"]) for pid, p in self.state["partners"].items()),
                      key=lambda x: (x[1].casefold(), x[0]))

    def weak_partners(self) -> list:
        """R14-M1: Partner, deren Passphrase die Regel ab 11.2 nicht erfüllt (vor 11.2 angelegt). Nur Hinweis."""
        return sorted(p["name"] for p in self.state["partners"].values() if core.passphrase_is_weak(p["pw"]))

    def partner(self, pid: str) -> tuple[str, str, str, bytes]:
        p = self.state["partners"].get(pid)
        if p is None:
            raise SigillumError(_("Partner nicht gefunden."))
        return p["name"], p["pw"], p["pin"], bytes.fromhex(p["kf"])

    def add_partner(self, name: str, keyfile: bytes, passphrase: str, pin: str) -> str:
        """Speichert die Faktoren eines gemeinsamen Schlüssels verschlüsselt in dieser Identität.
        Befund H1 bleibt erzwungen: nie die Schlüsseldatei oder Passphrase der Identität selbst."""
        name = core._check_name(name)
        core.read_keyfile(keyfile)
        core.check_passphrase(passphrase)
        core.check_pin(pin)
        d = core.keyfile_digest(keyfile)
        if d == self.kf_digest:
            raise SigillumError(_("Das ist die Schlüsseldatei deiner Identität – für einen Partner nie verwenden."))
        if self.same_passphrase(passphrase):
            raise SigillumError(_("Das ist die Passphrase deiner Identität – für einen Partner nie verwenden."))
        for p in self.state["partners"].values():
            if core.keyfile_digest(bytes.fromhex(p["kf"])) == d:
                raise SigillumError(_("Dieser gemeinsame Schlüssel ist schon als Partner „{0}“ gespeichert.").format(p['name']))
            if core.name_skeleton(p["name"]) == core.name_skeleton(name):
                raise SigillumError(_("Es gibt schon einen Partner mit (fast) gleichem Namen: „{0}“.").format(p['name']))
        if len(self.state["partners"]) >= MAX_PARTNERS:
            raise SigillumError(_("Höchstens {0} Partner.").format(MAX_PARTNERS))
        pid = secrets.token_hex(8)
        now = int(time.time())
        self.state["partners"][pid] = {"name": name, "kf": keyfile.hex(), "pw": core.canonical_passphrase(passphrase),
                                       "pin": unicodedata.normalize("NFC", pin).strip(), "created": now, "last_used": 0}
        return pid

    def touch_partner(self, pid: str, when: int | None = None):
        if pid in self.state["partners"]:
            self.state["partners"][pid]["last_used"] = int(time.time() if when is None else when)

    def remove_partner(self, pid: str):
        self.state["partners"].pop(pid, None)

    # ---------------------------------------------------------- Zufallsblätter (Befund L7)
    # Register: Blatt-Nr. -> Kennung der Nachricht, für die das Blatt benutzt wurde (beim Ver- UND Entschlüsseln,
    # Befund R2-1: beide Seiten haben dasselbe Blatt). "" = Nachricht unbekannt.
    def sheet_used(self, sid: str) -> bool:
        return sid in self.state["sheets"]

    def sheet_message(self, sid: str):
        return self.state["sheets"].get(sid)

    def mark_sheet(self, sid: str, msg: str):
        self.state["sheets"].setdefault(sid, msg)

    def sheet_opened(self, sid: str) -> int:
        """Wie oft mit diesem Blatt schon entschlüsselt wurde (Befund R3-2)."""
        return self.state["sheets_opened"].get(sid, 0)

    def mark_opened(self, sid: str):
        self.state["sheets_opened"][sid] = self.sheet_opened(sid) + 1


# ================================================================ Hilfen

def _empty(contact: core.Contact) -> dict:
    return {"my_keys": [], "next_seq": 1, "their": None, "sent": 0, "recv": 0, "last_ts": 0}


def _msg_key(ss: bytes, header: bytes, recip_fp: bytes, target_id: bytes) -> bytes:
    info = b"SIGILLUM-v3-msg" + header[:4] + recip_fp + target_id
    return core.hkdf(ss, info)


def _signed_data(header, recip_fp, sender_fp, announce, inner) -> bytes:
    return SIG_CONTEXT + header + recip_fp + sender_fp + announce + inner


def _their_keys(their: dict) -> list:
    """Angekündigte Schlüssel des Kontakts. Zustand bis 11.1: genau ein Schlüssel {"seq","id","pk"}."""
    if "keys" in their:
        return their["keys"]
    return [{"id": their["id"], "pk": their["pk"]}]


def once_keys_left(vault: "Vault", fp: str) -> int | None:
    """Wie viele Einmal-Schlüssel des Kontakts noch frei sind (None = noch keiner angekündigt, Basis-Schlüssel)."""
    cs = vault.state["contacts"].get(fp)
    if not cs or not cs.get("their"):
        return None
    keys = _their_keys(cs["their"])
    return max(0, len(keys) - 1 - cs["their"].get("next", 0))


def _cap(cs: dict):
    over = len(cs["my_keys"]) - MAX_OPEN_KEYS
    if over > 0:
        del cs["my_keys"][:over]


def reset_contact(vault: Vault, fp: str) -> None:
    """Schlüsselwechsel mit diesem Kontakt neu beginnen (z. B. nach Wiederherstellen eines Backups).
    Das Register geöffneter Nachrichten (state["seen"]) bleibt erhalten (Befund R3-1b)."""
    cs = vault.state["contacts"].pop(fp, None)
    if cs:
        rec = vault.state["seen"].setdefault(fp, {"ids": [], "ts": 0})
        rec["ts"] = max(rec["ts"], int(cs.get("last_ts", 0)))


def _require_verified(vault: Vault, fp: str) -> core.Contact:
    c, verified = vault.contact(fp)
    if c is None:
        raise SigillumError(_("Kontakt unbekannt – zuerst seinen öffentlichen Schlüssel importieren."))
    if not verified:
        raise SigillumError(_("Kontakt '{0}' ist nicht verifiziert – zuerst den Fingerabdruck vergleichen.").format(c.name))
    return c


# ================================================================ Senden

def encrypt(text: str, vault: Vault, recip_fp: str, now: float | None = None) -> bytes:
    """Verschlüsselt an den neuesten bekannten Empfangsschlüssel und kündigt einen neuen eigenen an.
    Verändert 'vault' – Aufrufer arbeitet auf einer Kopie (Vault.clone) und speichert vor der Herausgabe."""
    recip = _require_verified(vault, recip_fp)
    me = vault.identity
    my_fp = me.public().fp_raw()
    cs = vault.state["contacts"].setdefault(recip_fp, _empty(recip))
    their = cs["their"]
    if their:
        # Befund R12-N1: jeden Einmal-Schlüssel nur EINMAL benutzen, danach den Rückfallschlüssel (letzter im Vorrat)
        keys = _their_keys(their)
        i = min(their.get("next", 0), len(keys) - 1)
        t_id, t_pk = bytes.fromhex(keys[i]["id"]), bytes.fromhex(keys[i]["pk"])
        if "keys" in their:
            their["next"] = i + 1
    else:
        t_id, t_pk = BASE_ID, recip.kem_pk

    new_keys = [core.HybridKey.generate() for _u in range(POOL)]
    kids = []
    while len(kids) < POOL:                          # verschiedene, nie BASE_ID
        k = secrets.token_bytes(8)
        if k != BASE_ID and k not in kids:
            kids.append(k)
    seq = cs["next_seq"]
    if not 0 < seq < MAX_SEQ:
        raise SigillumError(_("Nachrichtenzähler erschöpft – beim Kontakt 'Schlüsselwechsel neu starten'."))
    announce = struct.pack(">QB", seq, POOL) + b"".join(k + nk.pk for k, nk in zip(kids, new_keys))
    inner, _u = core.pack_inner(text, my_fp[:16], now)

    ss, kem_ct = core.hkem_encap(t_pk)
    nonce = secrets.token_bytes(core.NONCE_LEN)
    header = core.MAGIC + bytes([core.VERSION, MODE]) + kem_ct + nonce
    signed = _signed_data(header, recip.fp_raw(), my_fp, announce, inner)
    plain = my_fp + me.sign(signed, SIG_CONTEXT) + announce + inner
    blob = header + core._aead_encrypt(plain, header, nonce, _msg_key(ss, header, recip.fp_raw(), t_id))

    created = int(time.time() if now is None else now)
    for j, (k, nk) in enumerate(zip(kids, new_keys)):
        cs["my_keys"].append({"seq": seq, "id": k.hex(), "seed": nk.seed.hex(), "created": created,
                              "once": j < POOL - 1})
    cs["next_seq"] = seq + 1
    cs["sent"] += 1
    _cap(cs)
    return blob


# ================================================================ Empfangen

def _candidates(vault: Vault, hint=None):
    """Basis-Schlüssel, dann je Kontakt die NEUESTEN Schlüssel zuerst (R14-N4: übliche Antworten sind schnell).
    hint = (fp, id) aus einem ersten Durchlauf (process_batch) wird zuerst probiert. Schlüssel-Objekte werden je
    Identität im Arbeitsspeicher zwischengespeichert (sie stehen ohnehin im entschlüsselten Zustand)."""
    cache = vault.__dict__.setdefault("_hk_cache", {})

    def hk(seed_hex):
        k = cache.get(seed_hex)
        if k is None:
            if len(cache) > 4 * MAX_OPEN_KEYS:
                cache.clear()
            k = cache[seed_hex] = core.HybridKey(bytes.fromhex(seed_hex))
        return k
    if hint is not None:
        fp, kid = hint
        for k in (vault.state["contacts"].get(fp) or {"my_keys": []})["my_keys"] if fp else []:
            if k["id"] == kid:
                yield fp, k, hk(k["seed"])
    yield None, None, vault.identity.kem
    for fp, cs in vault.state["contacts"].items():
        for k in reversed(cs["my_keys"]):
            yield fp, k, hk(k["seed"])


def open_message(blob: bytes, vault: Vault, hint=None) -> dict:
    """Schritt 1: entschlüsseln, Signaturen prüfen und den NEUEN Zustand berechnen – ohne etwas zu ändern."""
    mode = core.message_mode(blob)
    if mode not in MODES:
        raise SigillumError(_("Keine Kontakt-Nachricht."))
    fixed = PLAIN_FIXED_POOL if mode == core.MODE_CONTACT_POOL else PLAIN_FIXED
    if len(blob) < HDR_LEN + fixed + core.INNER_HDR + 16:
        raise SigillumError(_("Keine (vollständige) Kontakt-Nachricht."))
    header, ct = blob[:HDR_LEN], blob[HDR_LEN:]
    kem_ct, nonce = header[4:4 + core.HKEM_CT], header[4 + core.HKEM_CT:]
    my_fp = vault.identity.public().fp_raw()
    plain = owner = used = None
    for owner_fp, entry, xk in _candidates(vault, hint):
        try:
            ss = xk.decap(kem_ct)
            t_id = BASE_ID if entry is None else bytes.fromhex(entry["id"])
            plain = core._aead_decrypt(ct, header, nonce, _msg_key(ss, header, my_fp, t_id))
        except SigillumError:
            continue
        owner, used = owner_fp, entry
        break
    if plain is None:
        if core.h3(b"SIGILLUM-SPENT", header, 16).hex() in vault.state.get("spent", []):
            raise SigillumError(_("Diese Nachricht wurde schon geöffnet. Ihr Einmal-Schlüssel ist danach gelöscht "
                                  "worden (gewollt) – der Inhalt lässt sich deshalb nicht noch einmal anzeigen."))
        raise SigillumError(_("Nicht entschlüsselbar. Mögliche Ursachen: nicht an dich gerichtet, verändert, alt "
                              "oder doppelt (der Schlüssel wurde bereits gelöscht – gewollt), in falscher "
                              "Reihenfolge geöffnet, oder ein altes Backup der Identitätsdatei wurde eingespielt. "
                              "Abhilfe: fehlende Nachrichten zusammen einfügen oder beim Kontakt "
                              "'Schlüsselwechsel neu starten'."))
    if len(plain) < fixed + core.INNER_HDR:
        raise SigillumError(_("Nutzlast beschädigt."))
    sender_fp = plain[:32]
    sig = plain[32:32 + core.SIG_LEN]
    ann = plain[32 + core.SIG_LEN:fixed]
    inner = plain[fixed:]
    fp = sender_fp.hex()
    sender = _require_verified(vault, fp)
    if owner is not None and owner != fp:
        raise SigillumError(_("Schlüssel gehört zu einem anderen Kontakt – Nachricht abgelehnt."))
    signed = _signed_data(header, my_fp, sender_fp, ann, inner)
    core.verify_hybrid(sender, sig, signed, SIG_CONTEXT)
    result = core.unpack_inner(inner)
    if result["sender"] != sender_fp[:16]:
        raise SigillumError(_("Absenderangaben widersprüchlich."))
    (seq,) = struct.unpack(">Q", ann[:8])
    if mode == core.MODE_CONTACT_POOL:
        if ann[8] != POOL:
            raise SigillumError(_("Ungültige Schlüsselankündigung."))
        body = ann[9:]
        ann_keys = [(body[j * KEY_LEN:j * KEY_LEN + 8], body[j * KEY_LEN + 8:(j + 1) * KEY_LEN]) for j in range(POOL)]
    else:
        ann_keys = [(ann[8:16], ann[16:])]
    for a_id, a_pk in ann_keys:
        core.hkem_check_pk(a_pk)
    ids = [a for a, _u in ann_keys]
    if not 0 < seq < MAX_SEQ or BASE_ID in ids or len(set(ids)) != len(ids):
        raise SigillumError(_("Ungültige Schlüsselankündigung."))

    # Befund R3-1: schon geöffnete Nachricht? Dann melden und NICHTS ändern.
    rec = vault.state["seen"].get(fp) or {"ids": [], "ts": 0}
    mid = core.h3(b"SIGILLUM-SEEN", result["msgid"], 16).hex()
    base = {"sender_fp": fp, "sender_name": sender.name, "sender_seq": seq,
            "key": _("Basis-Schlüssel") if used is None else _("Wechselschlüssel Nr. {0}").format(used['seq'])}
    if mid in rec["ids"]:
        result.update(base, duplicate=True, partner_key_updated=False, partner_reset=False, replay=True, late=False,
                      deleted=0, open_keys=len((vault.state["contacts"].get(fp) or {"my_keys": []})["my_keys"]),
                      gap=[], gap_count=0, risk=False)
        return {"fp": fp, "work": None, "seen": None, "result": result, "used": None}

    work = copy.deepcopy(vault.state["contacts"].get(fp) or _empty(sender))
    prev_seq = work["their"]["seq"] if work["their"] else 0
    new_their = {"seq": seq, "keys": [{"id": a.hex(), "pk": p.hex()} for a, p in ann_keys], "next": 0}
    # Befund R3-1b: nach einem Neustart gilt der zuletzt gesehene Zeitstempel weiter als Untergrenze
    # Ein Zeitstempel weit in der Zukunft (falsche Uhr) darf die Untergrenze nicht vergiften.
    ts = min(result["timestamp"], int(time.time()) + MAX_SKEW)
    last_ts = max(work.get("last_ts", 0), rec["ts"])
    updated = reset = replay = late = False
    deleted = 0
    if work["their"] is None and used is None and ts <= last_ts:
        replay = True                                # alte Erstnachricht nach einem Neustart erneut eingespielt
    elif work["their"] is None or seq > work["their"]["seq"]:
        work["their"] = new_their                    # Zähler steigt -> kein Zurückdrehen möglich
        updated = True
    elif used is None and ts > last_ts:
        # Partner hat neu begonnen (Zustand verloren): an den Basis-Schlüssel und NEUER als alles bisher
        work["their"] = new_their
        deleted = len(work["my_keys"])
        work["my_keys"] = []
        updated = reset = True
    elif used is None:
        replay = True                                # alte Erstnachricht erneut eingespielt
    else:
        late = True                                  # ältere Nachricht, Schlüssel existiert noch
    work["last_ts"] = max(last_ts, ts)
    deleted_old = deleted                            # Schlüssel, mit denen ÄLTERE Nachrichten noch lesbar wären
    if used is not None:                             # ältere eigene Schlüssel SOFORT löschen
        older = [k for k in work["my_keys"] if k["seq"] < used["seq"]]
        keep = [k for k in work["my_keys"] if k["seq"] >= used["seq"]
                and not (k.get("once") and k["id"] == used["id"] and k["seq"] == used["seq"])]   # R12-N1: Einmal-Schlüssel
        deleted += len(work["my_keys"]) - len(keep)
        deleted_old += len(older)
        work["my_keys"] = keep
    work["recv"] += 1
    # Befund R2-3: Lücke nur als Anzahl + höchstens GAP_SHOW Nummern – auch bei absurd großem Sprung kein Speicherproblem
    gap_count = seq - prev_seq - 1 if (not reset and seq > prev_seq + 1) else 0
    gap = list(range(prev_seq + 1, prev_seq + 1 + min(gap_count, GAP_SHOW)))
    if replay:                                       # Wiederholung: nichts übernehmen
        work = copy.deepcopy(vault.state["contacts"].get(fp) or _empty(sender))
        deleted, gap_count, gap = 0, 0, []
    result.update(base, duplicate=False, partner_key_updated=updated, partner_reset=reset, replay=replay, late=late,
                  deleted=deleted, open_keys=len(work["my_keys"]), gap=gap, gap_count=gap_count,
                  risk=gap_count > 0 and deleted_old > 0)   # R14-N1: nur echte Gefahr für ältere Nachrichten
    new_rec = {"ids": (rec["ids"] + [mid])[-MAX_SEEN:], "ts": max(rec["ts"], ts)}
    spent = core.h3(b"SIGILLUM-SPENT", header, 16).hex() if used is not None and used.get("once") else None
    return {"fp": fp, "work": work, "seen": new_rec, "result": result, "spent": spent,
            "used": (owner, used["id"]) if used is not None else None}


def commit(vault: Vault, opened: dict) -> dict:
    if opened["work"] is not None:
        old = {k["seed"] for k in (vault.state["contacts"].get(opened["fp"]) or {"my_keys": []})["my_keys"]}
        new = {k["seed"] for k in opened["work"]["my_keys"]}
        cache = vault.__dict__.get("_hk_cache") or {}
        for seed in old - new:                       # gelöschte Schlüssel auch aus dem Zwischenspeicher entfernen
            cache.pop(seed, None)
        vault.state["contacts"][opened["fp"]] = opened["work"]
        vault.state["seen"][opened["fp"]] = opened["seen"]
        if opened.get("spent"):                      # R12-N1: gelöschte Einmal-Schlüssel – Wiederholung erkennbar
            vault.state["spent"] = (vault.state.get("spent", []) + [opened["spent"]])[-MAX_SEEN:]
    return opened["result"]


def decrypt(blob: bytes, vault: Vault) -> dict:
    return commit(vault, open_message(blob, vault))


def process_batch(items: list, vault: Vault) -> list:
    """items: Liste von (Index, blob). Erst alle prüfen, dann je Absender nach dessen Nummer sortiert übernehmen.
    Verändert 'vault' – Aufrufer arbeitet auf einer Kopie."""
    trial, out = [], []
    for idx, blob in items:
        try:
            o = open_message(blob, vault)
            r = o["result"]
            trial.append((r["sender_fp"], r["sender_seq"], idx, blob, o.get("used")))
        except SigillumError as e:
            out.append({"index": idx, "error": str(e)})
    for fp, seq, idx, blob, hint in sorted(trial, key=lambda t: t[:3]):
        try:
            out.append({"index": idx, "result": commit(vault, open_message(blob, vault, hint))})   # R14-N4
        except SigillumError as e:
            out.append({"index": idx, "error": str(e)})
    return out


def find_copies(folders: list, salt: bytes, exclude: str, limit: int = 20000) -> list:
    """Befund R4-6: Kopien DIESER Identität (gleiches Argon2-Salz im Kopf, Modus 3 oder 5) in Ordnern suchen.
    Liest nur den Dateikopf; nichts wird entschlüsselt. Ergebnis: Liste von Pfaden."""
    import os
    hits, seen, n = [], set(), 0
    ex = os.path.normcase(os.path.realpath(exclude)) if exclude else None
    for folder in folders:
        for root, dirs, files in os.walk(folder):
            for f in files:
                n += 1
                if n > limit:
                    return hits
                if not f.lower().endswith(".said"):
                    continue
                p = os.path.join(root, f)
                rp = os.path.normcase(os.path.realpath(p))
                if rp == ex or rp in seen:
                    continue
                seen.add(rp)
                try:
                    with open(p, "rb") as fh:
                        head = fh.read(6 + core.SALT_LEN)
                except OSError:
                    continue
                if (len(head) == 6 + core.SALT_LEN and head[:3] == core.MAGIC + bytes([core.VERSION])
                        and head[3] in (core.MODE_IDENTITY, core.MODE_IDENTITY_FIDO)
                        and hmac.compare_digest(head[6:], salt)):
                    hits.append(p)
    return hits


def classify_copy(path: str, vault: "Vault") -> str:
    """"weak" = öffnet ohne YubiKey oder mit altem Key/Code (löschen), "same" = gleicher Schutz wie die aktuelle
    Datei (ältere Sicherung – nicht automatisch löschen, sonst geht womöglich die einzige Sicherung verloren)."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read(MAX_VAULT + 1)
        if file_mode(blob) != core.MODE_IDENTITY_FIDO or not vault.fido:
            return "weak" if vault.fido else "same"
        h = parse_fido_header(blob)
    except (OSError, SigillumError):
        return "weak"
    mine = [(s["type"], s["meta"], s["nonce"], s["wrapped"]) for s in vault._prot["slots"]]
    theirs = [(s["type"], s["meta"], s["nonce"], s["wrapped"]) for s in h["slots"]]
    return "same" if (mine == theirs and h["prf_salt"] == vault._prot["prf_salt"]) else "weak"
