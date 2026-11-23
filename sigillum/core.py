"""Sigillum Arcanum - Krypto-Kern (Format v3, App-Version 11.2) – ausgerichtet an BSI TR-02102-1 (2026-01).

Nur geprüfte Bausteine, keine selbst erfundene Kryptografie:
  - PyNaCl (libsodium): Argon2id (TR-02102-1 B.1.2)
  - pyca/cryptography (OpenSSL):
      AES-256-GCM-SIV (Tab. 3.1/3.2), HKDF-SHA-512 (Tab. B.1),
      ML-KEM-1024 (Abschn. 2.4.3, Tab. 2.7) + ECDH über brainpoolP512r1 (Abschn. 2.3.6, Tab. B.3) – NUR hybrid,
      ML-DSA-87 „hedged“ (Tab. 5.7) + ECDSA über brainpoolP512r1 mit SHA3-512 (Tab. 5.5) – NUR hybrid
  - hashlib: SHA3-256/-512, SHAKE256 (Tab. 4.1)
  - Hybrid-Kombinierer: KeyCombine nach NIST SP 800-227, Abschn. 4.6.2, Gl. (15), mit H = HKDF-SHA-512
    (zulässig nach TR-02102-1 Tab. 2.1).

Modi:
  1 = Gemeinsamer Schlüssel (Passphrase + PIN + Schlüsseldatei)
  3 = Identitätsdatei (eigene, GETRENNTE Faktoren; siehe ratchet.Vault)
  4 = Kontakt-Nachricht mit Schlüsselwechsel (siehe ratchet.py)
  5 = Identitätsdatei mit YubiKey-Hüllen (siehe ratchet.Vault, fidokey.py)
"""
import hashlib
import math
import os
import re
import secrets
import struct
import time
import unicodedata

import nacl.pwhash.argon2id as argon2id
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SA"
VERSION = 3                                   # Format v3 seit App-Version 10 (BSI-Umbau); v11: Zustand v4
MODE_SHARED, MODE_IDENTITY, MODE_CONTACT, MODE_IDENTITY_FIDO = 1, 3, 4, 5
MODE_CONTACT_POOL = 6                         # v11.2: Kontakt-Nachricht mit Vorrat an Einmal-Schlüsseln (R12-N1)
NONCE_LEN = 12                                # AES-GCM-SIV: 96-Bit-Nonce, zufällig (TR-02102-1 Abschn. 3.1.2)
TAG_LEN = 16
SALT_LEN = argon2id.SALTBYTES                 # 16
KEYFILE_MAGIC = b"SAKEY2\x00\x00"
KDF_OPS, KDF_MEMLOG = 4, 30                   # Argon2id: 4 Durchläufe, 1 GiB
ALLOWED_KDF = {(KDF_OPS, KDF_MEMLOG)}         # nur diese Werte werden angenommen (Befund L2)
MIN_BUCKET = 128
MAX_TEXT_BYTES = 256 * 1024
MAX_MESSAGE = 2 * 1024 * 1024
MIN_WORDS = 6                                 # 6 Diceware-Wörter = 77,5 Bit (Befund M4)
MIN_PIN = 6                                   # Länge in Anlehnung an TR-02102-1 Tab. 6.2; da offline angreifbar, gilt
                                              # Bem. 6.4 (iii): Schutz durch Besitzfaktoren (Schlüsseldatei, YubiKey)
MAX_NAME = 64
PURPOSE_SHARED, PURPOSE_IDENTITY = b"shared", b"identity"
PURPOSE_DAILY, PURPOSE_QUICK = b"daily", b"quick"           # v11: Alltags-Hülle (ohne Passphrase), Schnell-Entsperren
_HERE = os.path.dirname(os.path.abspath(__file__))


class SigillumError(Exception):
    """Fehler mit bewusst allgemeiner Meldung (verrät nicht, welcher Faktor falsch war)."""


# ---------------------------------------------------------------- Hilfsfunktionen

def _lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _nfc(s: str) -> bytes:
    return unicodedata.normalize("NFC", s).encode("utf-8")


def _aead_encrypt(plain: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    """AES-256-GCM-SIV: bleibt vertraulich und integer, selbst wenn sich eine Nonce wiederholen sollte."""
    if len(key) != 32 or len(nonce) != NONCE_LEN:
        raise SigillumError("Interner Fehler: Schlüssel- oder Nonce-Länge.")
    return AESGCMSIV(key).encrypt(nonce, plain, aad)


def _aead_decrypt(ct: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    """Erst Prüfwert, dann Klartext (kein Fehlerorakel, TR-02102-1 Bem. 3.1/3.3). Einheitliche Meldung."""
    try:
        if len(key) != 32 or len(nonce) != NONCE_LEN or len(ct) < TAG_LEN:
            raise ValueError
        return AESGCMSIV(key).decrypt(nonce, ct, aad)
    except (InvalidTag, ValueError, OverflowError):
        raise SigillumError("Entschlüsseln fehlgeschlagen: falscher Schlüssel oder veränderte Nachricht.") from None


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    """HKDF mit SHA-512 (TR-02102-1 Tab. B.1); Ausgabelänge L (Standard 32 Byte) – zulässig nach RFC 5869."""
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)


def h3(label: bytes, data: bytes, n: int = 32) -> bytes:
    """SHA3 mit Zweck-Präfix (Längenpräfix verhindert Mehrdeutigkeiten). n = 32 -> SHA3-256, sonst SHA3-512."""
    d = (hashlib.sha3_256 if n <= 32 else hashlib.sha3_512)(_lp(label) + data).digest()
    return d[:n]


# ---------------------------------------------------------------- Passphrase und PIN (Befund M4)

_WORDS = None


def wordlist() -> list:
    global _WORDS
    if _WORDS is None:
        with open(os.path.join(_HERE, "data", "eff_large_wordlist.txt"), encoding="utf-8") as f:
            _WORDS = [w.strip() for w in f if w.strip()]
        if len(_WORDS) != 7776 or len(set(_WORDS)) != 7776:
            raise SigillumError("Wortliste beschädigt.")
    return _WORDS


def canonical_passphrase(pw: str) -> str:
    """Groß/klein und mehrfache Leerzeichen spielen keine Rolle. Bindestriche bleiben erhalten,
    weil vier Wörter der Liste einen enthalten (z. B. 't-shirt')."""
    return " ".join(unicodedata.normalize("NFC", pw).casefold().split())


def _distinct_bits(k: int, n: int = 7776) -> float:
    """Entropie von k VERSCHIEDENEN, zufällig gezogenen Wörtern aus n (Ziehen ohne Zurücklegen)."""
    return sum(math.log2(n - i) for i in range(k))


MIN_PASSPHRASE_BITS = _distinct_bits(MIN_WORDS)            # 6 verschiedene Wörter: 77,5 Bit


def passphrase_bits(pw: str) -> float:
    """Stärke in Bit, NUR für Passphrasen aus der Wortliste (sonst 0 – nicht schätzbar). Befund R12-M1: Es zählen nur
    VERSCHIEDENE Wörter – „password“ sechsmal hat nicht 77,5 Bit, sondern praktisch keine."""
    words = canonical_passphrase(pw).split(" ")
    known = set(wordlist())
    if not words or words == [""] or any(w not in known for w in words):
        return 0.0
    if len(set(words)) != len(words):
        return _distinct_bits(len(set(words))) if len(set(words)) > 1 else 0.0
    return _distinct_bits(len(words))


def check_passphrase(pw: str):
    """Für NEU verwendete Passphrasen (Identität, gemeinsamer Schlüssel, Partner). TR-02102-1 Bem. 6.2."""
    words = canonical_passphrase(pw).split(" ")
    known = set(wordlist())
    if not words or any(w not in known for w in words) or len(set(words)) < MIN_WORDS:
        raise SigillumError(f"Passphrase zu schwach: Sie muss aus mindestens {MIN_WORDS} VERSCHIEDENEN Wörtern der "
                            "Diceware-Liste bestehen (Knopf 'Erzeugen'). Wiederholte Wörter zählen nur einmal.")


def check_passphrase_stored(pw: str):
    """Beim LADEN bereits gespeicherter Partner-Einträge (vor 11.2 angelegt): alte Regel, damit sich niemand aussperrt
    (bis 11.1 konnte der Generator mit Wahrscheinlichkeit ~0,3 % ein Wort doppelt ziehen)."""
    words = canonical_passphrase(pw).split(" ")
    known = set(wordlist())
    if len(words) < MIN_WORDS or any(w not in known for w in words):     # exakt die Regel bis 11.1 (R14-M1)
        raise SigillumError("Passphrase ungültig.")


def passphrase_is_weak(pw: str) -> bool:
    """Für Hinweise: gespeicherte Passphrase erfüllt die Regel ab 11.2 nicht (z. B. ein Wort mehrfach)."""
    try:
        check_passphrase(pw)
        return False
    except SigillumError:
        return True


def generate_passphrase(words: int = 7) -> str:
    """Zufällig aus der EFF-Liste, ohne Zurücklegen (keine Wiederholung): 7 Wörter = 90,4 Bit."""
    return " ".join(secrets.SystemRandom().sample(wordlist(), words))


def check_pin(pin: str):
    if len(unicodedata.normalize("NFC", pin).strip()) < MIN_PIN:
        raise SigillumError(f"Die PIN muss mindestens {MIN_PIN} Zeichen haben.")


# Befund R12-N2 / R14-M2, R14-N3: naheliegende PINs (TR-02102-1 Bem. 6.2). Geprüft wird auch ohne Trennzeichen
# und mit „Leetspeak“-Ersatz; Ziffern zählen nur als ASCII 0–9 (² ³ ① usw. sind Sonderzeichen, kein Absturz).
_WEAK_WORDS = {"passwort", "password", "geheim", "sommer", "winter", "hallo", "admin", "login", "secret", "sigillum",
               "schatz", "liebe", "love", "test", "abc", "qwertz", "qwerty", "asdfgh", "yxcvbn", "zxcvbn", "pin"}
_KEY_ROWS = ("1234567890", "qwertzuiop", "qwertyuiop", "asdfghjkl", "yxcvbnm", "zxcvbnm", "789456123", "147258369",
             "741852963", "159357", "753951", "963852741", "321654987")
_PAD = {"7": (0, 0), "8": (0, 1), "9": (0, 2), "4": (1, 0), "5": (1, 1), "6": (1, 2), "1": (2, 0), "2": (2, 1),
        "3": (2, 2), "0": (3, 1)}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})


def _ascii_digits(s: str) -> bool:
    return s.isascii() and s.isdigit()


def _is_date(d: str) -> bool:
    """Datumsangaben in naheliegenden Formaten: TTMMJJ, MMTTJJ, JJMMTT, TTMMJJJJ, JJJJMMTT, MMTTJJJJ."""
    if not _ascii_digits(d):
        return False

    def ok(day, mon):
        return 1 <= mon <= 12 and 1 <= day <= 31
    if len(d) == 6:
        a, b, c = int(d[0:2]), int(d[2:4]), int(d[4:6])
        return ok(a, b) or ok(b, a) or ok(c, b)
    if len(d) == 8:
        return ((ok(int(d[0:2]), int(d[2:4])) and 1900 <= int(d[4:8]) <= 2099)
                or (ok(int(d[2:4]), int(d[0:2])) and 1900 <= int(d[4:8]) <= 2099)
                or (1900 <= int(d[0:4]) <= 2099 and ok(int(d[6:8]), int(d[4:6]))))
    return False


def _is_sep_date(p: str) -> bool:
    """Datum mit Trennzeichen, z. B. 12.12.1985, 1.1.00, 1985-12-24."""
    m = re.fullmatch(r"(\d{1,4})[.\-/ ](\d{1,2})[.\-/ ](\d{1,4})", p)
    if not m or not p.isascii():
        return False
    a, b, c = (int(x) for x in m.groups())
    if len(m.group(1)) == 4:
        a, c = c, a                                     # JJJJ-MM-TT -> TT, MM, JJJJ
    return 1 <= b <= 12 and 1 <= a <= 31 or 1 <= a <= 12 and 1 <= b <= 31


def _weak_run(t: str) -> bool:
    """Ein Teilstück (nur Ziffern oder nur Buchstaben) ist naheliegend."""
    if len(set(t)) <= 1:
        return True
    if any(t in row or t in row[::-1] for row in _KEY_ROWS):
        return True
    if _ascii_digits(t):
        steps = {(int(b) - int(a)) % 10 for a, b in zip(t, t[1:])}
        if len(steps) == 1:                             # 123456, 246802, 975319 … (konstante Schrittweite)
            return True
    elif t.isascii() and t.isalpha():
        steps = {ord(b) - ord(a) for a, b in zip(t, t[1:])}
        if len(steps) == 1 and steps <= {1, -1}:
            return True
    return t.translate(_LEET) in _WEAK_WORDS or t in _WEAK_WORDS


def pin_problem(pin: str) -> str | None:
    """Befund R12-N2: naheliegende PINs erkennen (TR-02102-1 Bem. 6.2). Rückgabe: Grund oder None. Wirft nie."""
    p = unicodedata.normalize("NFC", pin).strip()
    if len(p) < MIN_PIN:
        return f"Die PIN muss mindestens {MIN_PIN} Zeichen haben."
    low = p.casefold()
    core_ = re.sub(r"[\s.\-/_:,]", "", low)              # ohne Trennzeichen prüfen (1 2 3 4 5 6, 123-456)
    if _is_sep_date(low) or _is_date(core_):
        return "Die PIN sieht aus wie ein Datum (z. B. ein Geburtstag)."
    if len(set(core_)) <= 2:
        return "Die PIN besteht aus nur ein oder zwei verschiedenen Zeichen."
    for per in (2, 3, 4):
        if len(core_) > per and core_ == (core_[:per] * len(core_))[:len(core_)]:
            return "Die PIN wiederholt nur ein kurzes Muster."
    if _ascii_digits(core_) and len(core_) <= 8 and all(abs(_PAD[a][0] - _PAD[b][0]) <= 1
                                                        and abs(_PAD[a][1] - _PAD[b][1]) <= 1
                                                        for a, b in zip(core_, core_[1:])):
        return "Die PIN ist ein Weg über benachbarte Tasten des Ziffernblocks."
    if len(core_) <= 3 * len(set(core_)) and core_[:len(core_) // 2] == core_[len(core_) // 2:][::-1]:
        return "Die PIN ist ein Spiegelmuster (z. B. 123321)."
    runs = re.findall(r"[^\W\d_]+|\d+|[\W_]+", core_)
    if all(_weak_run(r) for r in runs if r):
        return "Die PIN besteht aus naheliegenden Teilen (Zahlen-/Tastenfolge, Wiederholung oder häufiges Wort)."
    if len(core_) % 2 == 0 and _weak_run(core_[0::2]) and _weak_run(core_[1::2]):
        return "Die PIN ist ein verschränktes Muster (z. B. 1q2w3e, a1b2c3)."
    if core_.translate(_LEET) in _WEAK_WORDS:
        return "Die PIN ist ein häufiges Wort."
    return None


def check_pin_new(pin: str):
    """Für eine NEU gewählte App-PIN (Identität): Länge UND nicht naheliegend."""
    why = pin_problem(pin)
    if why:
        raise SigillumError(why + " Bitte eine zufällige PIN wählen.")


def generate_pin(n: int = 6) -> str:
    while True:
        p = "".join(secrets.choice("0123456789") for _ in range(n))
        if pin_problem(p) is None:
            return p


# ---------------------------------------------------------------- Schlüsseldatei

def new_keyfile() -> bytes:
    body = KEYFILE_MAGIC + secrets.token_bytes(32)
    return body + h3(b"SIGILLUM-KEYFILE-CHK", body, 4)


def read_keyfile(data: bytes) -> bytes:
    if len(data) == 44 and data[:8] == b"SAKEY1\x00\x00":
        raise SigillumError("Schlüsseldatei aus einer älteren App-Version (vor Version 10) – bitte neu erzeugen.")
    if len(data) != 44 or data[:8] != KEYFILE_MAGIC:
        raise SigillumError("Das ist keine gültige Schlüsseldatei.")
    if h3(b"SIGILLUM-KEYFILE-CHK", data[:40], 4) != data[40:]:
        raise SigillumError("Die Schlüsseldatei ist beschädigt (Prüfsumme falsch).")
    return data[8:40]


def keyfile_digest(keyfile: bytes) -> str:
    """Nicht geheime Kennung einer Schlüsseldatei (zum Erkennen doppelter Verwendung, Befund H1)."""
    return h3(b"SIGILLUM-KFID", read_keyfile(keyfile)).hex()


def derive_key(passphrase: str, pin: str, keyfile: bytes, salt: bytes, purpose: bytes,
               ops: int | None = None, memlog: int | None = None) -> bytes:
    """Alle drei Faktoren -> Argon2id -> 256-Bit-Schlüssel. 'purpose' trennt Identität und Nachrichten."""
    ops = KDF_OPS if ops is None else ops
    memlog = KDF_MEMLOG if memlog is None else memlog
    if purpose not in (PURPOSE_SHARED, PURPOSE_IDENTITY):
        raise SigillumError("Unbekannter Verwendungszweck.")
    if (ops, memlog) not in ALLOWED_KDF:
        raise SigillumError("Unzulässige Schlüsselableitungs-Parameter.")
    if not passphrase or not pin:
        raise SigillumError("Passphrase und PIN dürfen nicht leer sein.")
    secret = read_keyfile(keyfile)
    material = (b"SIGILLUM-ARCANUM-v3\x00" + _lp(purpose) + _lp(canonical_passphrase(passphrase).encode("utf-8"))
                + _lp(_nfc(pin.strip())) + _lp(secret))
    try:
        return argon2id.kdf(32, material, salt, opslimit=ops, memlimit=1 << memlog)
    except MemoryError:
        raise SigillumError("Nicht genug Arbeitsspeicher für die Schlüsselableitung (1 GiB nötig).") from None


def _argon(material: bytes, salt: bytes, ops: int, memlog: int) -> bytes:
    if (ops, memlog) not in ALLOWED_KDF:
        raise SigillumError("Unzulässige Schlüsselableitungs-Parameter.")
    if len(salt) != SALT_LEN:
        raise SigillumError("Interner Fehler: Salz-Länge.")
    try:
        return argon2id.kdf(32, material, salt, opslimit=ops, memlimit=1 << memlog)
    except MemoryError:
        raise SigillumError("Nicht genug Arbeitsspeicher für die Schlüsselableitung (1 GiB nötig).") from None


def derive_daily_key(pin: str, keyfile: bytes, salt: bytes, ops: int | None = None, memlog: int | None = None) -> bytes:
    """v11, Alltags-Hülle (nur zusammen mit dem YubiKey-Geheimnis verwendet): PIN + Schlüsseldatei, OHNE Passphrase.
    Eigener Zweck "daily" – nie gleich dem Identitätsschlüssel A."""
    ops = KDF_OPS if ops is None else ops
    memlog = KDF_MEMLOG if memlog is None else memlog
    if not pin:
        raise SigillumError("PIN darf nicht leer sein.")
    secret = read_keyfile(keyfile)
    material = b"SIGILLUM-ARCANUM-v3\x00" + _lp(PURPOSE_DAILY) + _lp(_nfc(pin.strip())) + _lp(secret)
    return _argon(material, salt, ops, memlog)


def derive_quick_key(pin: str, salt: bytes) -> bytes:
    """v11, Schnell-Entsperren: Schlüssel nur aus der PIN, für eine im Arbeitsspeicher versiegelte Sitzung."""
    if not pin:
        raise SigillumError("PIN darf nicht leer sein.")
    material = b"SIGILLUM-ARCANUM-v3\x00" + _lp(PURPOSE_QUICK) + _lp(_nfc(pin.strip()))
    return _argon(material, salt, KDF_OPS, KDF_MEMLOG)


def seal(key: bytes, data: bytes, label: bytes) -> bytes:
    """AES-256-GCM-SIV mit Zufalls-Nonce; label wird als AAD gebunden."""
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + _aead_encrypt(data, label, nonce, key)


def unseal(key: bytes, blob: bytes, label: bytes) -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise SigillumError("Entschlüsseln fehlgeschlagen: falscher Schlüssel oder veränderte Nachricht.")
    return _aead_decrypt(blob[NONCE_LEN:], label, blob[:NONCE_LEN], key)


# ---------------------------------------------------------------- Nutzlast mit Längen-Tarnung

INNER_HDR = 1 + 1 + 8 + 16 + 16 + 4


def pack_inner(text: str, sender: bytes, now: float | None = None) -> tuple[bytes, bytes]:
    data = text.encode("utf-8")
    if len(data) > MAX_TEXT_BYTES:
        raise SigillumError("Text zu lang.")
    if len(sender) != 16:
        raise SigillumError("Interne Absenderkennung ungültig.")
    msgid = secrets.token_bytes(16)
    ts = int(time.time() if now is None else now)
    raw = struct.pack(">BBQ", 3, 0, ts) + msgid + sender + struct.pack(">I", len(data)) + data
    size = MIN_BUCKET
    while size < len(raw):
        size *= 2
    return raw + b"\x00" * (size - len(raw)), msgid


def unpack_inner(raw: bytes) -> dict:
    if len(raw) < INNER_HDR or raw[0] != 3:
        raise SigillumError("Unbekanntes Nutzlast-Format.")
    _, _, ts = struct.unpack(">BBQ", raw[:10])
    msgid, sender = raw[10:26], raw[26:42]
    (n,) = struct.unpack(">I", raw[42:46])
    if INNER_HDR + n > len(raw) or any(raw[INNER_HDR + n:]):
        raise SigillumError("Nutzlast beschädigt.")
    try:
        text = raw[INNER_HDR:INNER_HDR + n].decode("utf-8")
    except UnicodeDecodeError:
        raise SigillumError("Nutzlast beschädigt.") from None
    return {"text": text, "timestamp": ts, "msgid": msgid, "sender": sender}


# ---------------------------------------------------------------- Kopf und Modus

def _shared_header(mode, ops, memlog, salt, nonce):
    return MAGIC + bytes([VERSION, mode, ops, memlog]) + salt + nonce


def message_mode(blob: bytes) -> int:
    if len(blob) < 6 or blob[:2] != MAGIC:            # Befund R8-N1: jeder Kopf hat mindestens 6 Byte
        raise SigillumError("Das ist keine Sigillum-Nachricht (oder die Datei ist unvollständig).")
    if blob[2] in (1, 2):
        raise SigillumError("Datei aus einer älteren App-Version (vor Version 10) – dieses Format wird nicht mehr "
                            "unterstützt.")
    if blob[2] != VERSION:
        raise SigillumError("Nachricht aus einer neueren Version der App.")
    if len(blob) > MAX_MESSAGE and blob[3] not in (MODE_IDENTITY, MODE_IDENTITY_FIDO):
        raise SigillumError("Nachricht zu groß.")
    return blob[3]


def _parse_shared_header(blob, mode):
    hl = 6 + SALT_LEN + NONCE_LEN
    if message_mode(blob) != mode or len(blob) < hl + 16:
        raise SigillumError("Unbekanntes oder falsches Nachrichtenformat.")
    ops, memlog = blob[4], blob[5]
    if (ops, memlog) not in ALLOWED_KDF:
        raise SigillumError("Unzulässige Schlüsselableitungs-Parameter in der Datei – abgelehnt.")
    salt = blob[6:6 + SALT_LEN]
    nonce = blob[6 + SALT_LEN:hl]
    return blob[:hl], ops, memlog, salt, nonce, blob[hl:]


# ---------------------------------------------------------------- Modus 1: gemeinsamer Schlüssel

def encrypt_shared(text: str, passphrase, pin, keyfile, sender: bytes, stored: bool = False) -> bytes:
    """'sender' = Gerätekennung (16 Byte). Damit erkennt der Empfänger zurückgespiegelte eigene Nachrichten.
    stored=True: Faktoren eines in der Identität gespeicherten Partners (vor 11.2 angelegt) – alte Regel, kein Aussperren."""
    (check_passphrase_stored if stored else check_passphrase)(passphrase)
    check_pin(pin)
    inner, _ = pack_inner(text, sender)
    salt, nonce = secrets.token_bytes(SALT_LEN), secrets.token_bytes(NONCE_LEN)
    key = derive_key(passphrase, pin, keyfile, salt, PURPOSE_SHARED)
    header = _shared_header(MODE_SHARED, KDF_OPS, KDF_MEMLOG, salt, nonce)
    return header + _aead_encrypt(inner, header, nonce, key)


def decrypt_shared(blob: bytes, passphrase, pin, keyfile) -> dict:
    header, ops, memlog, salt, nonce, ct = _parse_shared_header(blob, MODE_SHARED)
    key = derive_key(passphrase, pin, keyfile, salt, PURPOSE_SHARED, ops, memlog)
    return unpack_inner(_aead_decrypt(ct, header, nonce, key))


# ---------------------------------------------------------------- Hybrid-KEM: ML-KEM-1024 + ECDH-brainpoolP512r1
#
# TR-02102-1 Abschn. 2.2/2.4: ML-KEM nur hybrid, Kombination z. B. per KeyCombine aus NIST SP 800-227
# (Abschn. 4.6.1 Gl. (9), 4.6.2 Gl. (15)): K = H(K1, K2, c1, c2, ek1, ek2, domain_sep), H = KDF.
# Hier: H = HKDF-SHA-512 mit IKM = K1|K2|c1|c2|ek1|ek2 (alle Längen fest, daher eindeutig), info = domain_sep.
# Der klassische Teil ist ECDH als KEM: c2 = öffentlicher Wegwerf-Punkt des Senders, K2 = x-Koordinate.

CURVE = ec.BrainpoolP512R1()
EC_ORDER = int("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471"
               "DB1D381085DDADDB58796829CA90069", 16)          # RFC 5639, Ordnung q des Basispunkts (prim)
EC_PT = 1 + 2 * 64                            # unkomprimierter Punkt 04|x|y
EC_SIG = 2 * 64                               # r|s fest je 64 Byte
MLKEM_PK, MLKEM_CT = 1568, 1568
HKEM_PK = MLKEM_PK + EC_PT                    # 1697
HKEM_CT = MLKEM_CT + EC_PT                    # 1697
HKEM_DOMAIN = b"SIGILLUM-ARCANUM-v3/HKEM/ML-KEM-1024+ECDH-brainpoolP512r1/SP800-227-KeyCombine/HKDF-SHA-512"


def _pt(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def ec_load_point(b: bytes) -> ec.EllipticCurvePublicKey:
    """Punktprüfung (TR-02102-1 Abschn. 2.3.6): nur unkomprimiert, feste Länge, auf der Kurve (OpenSSL prüft),
    nicht der Fernpunkt. Kofaktor von brainpoolP512r1 ist 1 – jeder Kurvenpunkt != O hat Primordnung q."""
    if len(b) != EC_PT or b[0] != 4:
        raise SigillumError("Öffentlicher Schlüssel ungültig.")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b)
    except ValueError:
        raise SigillumError("Öffentlicher Schlüssel ungültig.") from None


def ec_scalar(seed_material: bytes) -> ec.EllipticCurvePrivateKey:
    """Privater Skalar d in {1..q-1} aus 96 Byte (768 Bit) Zufall: Abweichung von der Gleichverteilung < 2^-256
    (Verfahren analog TR-02102-1 Abschn. B.4: 64+ zusätzliche Bit, dann Reduktion)."""
    if len(seed_material) != 96:
        raise SigillumError("Interner Fehler: Skalar-Material.")
    d = int.from_bytes(seed_material, "big") % (EC_ORDER - 1) + 1
    return ec.derive_private_key(d, CURVE)


def _ecdh(priv: ec.EllipticCurvePrivateKey, pub: ec.EllipticCurvePublicKey) -> bytes:
    ss = priv.exchange(ec.ECDH(), pub)
    if len(ss) != 64 or not any(ss):
        raise SigillumError("Schlüsselaustausch ungültig.")
    return ss


def _key_combine(k1, k2, c1, c2, ek1, ek2) -> bytes:
    """SP 800-227 Gl. (15) – Reihenfolge exakt: K1, K2, c1, c2, ek1, ek2, domain_sep."""
    if (len(k1), len(k2), len(c1), len(c2), len(ek1), len(ek2)) != (32, 64, MLKEM_CT, EC_PT, MLKEM_PK, EC_PT):
        raise SigillumError("Interner Fehler: Kombinierer-Eingaben.")
    return hkdf(k1 + k2 + c1 + c2 + ek1 + ek2, HKEM_DOMAIN, 32)


class HybridKey:
    """Entschlüsselungsschlüssel aus einem 32-Byte-Seed (expandiert per SHAKE256, getrennte Teile je Verfahren)."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise SigillumError("Schlüssel-Seed ungültig.")
        self.seed = seed
        e = hashlib.shake_256(_lp(b"SIGILLUM-v3-HKEM-expand") + seed).digest(64 + 96)
        self._m = mlkem.MLKEM1024PrivateKey.from_seed_bytes(e[:64])
        self._x = ec_scalar(e[64:160])
        self.pk_m = self._m.public_key().public_bytes_raw()
        self.pk_x = _pt(self._x.public_key())
        self.pk = self.pk_m + self.pk_x

    @classmethod
    def generate(cls):
        return cls(secrets.token_bytes(32))

    def decap(self, ct: bytes) -> bytes:
        if len(ct) != HKEM_CT:
            raise SigillumError("Schlüsselaustausch ungültig.")
        c1, c2 = ct[:MLKEM_CT], ct[MLKEM_CT:]
        try:
            k1 = self._m.decapsulate(c1)                 # ML-KEM: implizite Ablehnung (FIPS 203)
        except ValueError:
            raise SigillumError("Schlüsselaustausch ungültig.") from None
        k2 = _ecdh(self._x, ec_load_point(c2))
        return _key_combine(k1, k2, c1, c2, self.pk_m, self.pk_x)


def hkem_check_pk(pk: bytes):
    """Öffentlichen Hybrid-Schlüssel streng prüfen (ML-KEM-Modulus-Prüfung durch OpenSSL, EC-Punktprüfung)."""
    if len(pk) != HKEM_PK:
        raise SigillumError("Öffentlicher Schlüssel ungültig.")
    try:
        mlkem.MLKEM1024PublicKey.from_public_bytes(pk[:MLKEM_PK])
    except ValueError:
        raise SigillumError("Öffentlicher Schlüssel ungültig.") from None
    ec_load_point(pk[MLKEM_PK:])


def hkem_encap(pk: bytes) -> tuple[bytes, bytes]:
    hkem_check_pk(pk)
    ek1, ek2 = pk[:MLKEM_PK], pk[MLKEM_PK:]
    k1, c1 = mlkem.MLKEM1024PublicKey.from_public_bytes(ek1).encapsulate()
    eph = ec.generate_private_key(CURVE)
    k2 = _ecdh(eph, ec_load_point(ek2))
    c2 = _pt(eph.public_key())
    return _key_combine(k1, k2, c1, c2, ek1, ek2), c1 + c2


# ---------------------------------------------------------------- Hybride Signatur (TR-02102-1 Abschn. 5.3.4)
# Konkatenation ECDSA | ML-DSA; gültig nur, wenn BEIDE gültig sind. Schlüssel nur für diesen Zweck.

def ec_sign(priv: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Befund R8-H3: kanonische Form (s <= q/2). (r, s) und (r, q-s) sind beide gültig; nur eine wird erzeugt
    und angenommen, damit es zu jeder Signatur genau eine gültige Darstellung gibt."""
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA3_512())))
    if s > EC_ORDER // 2:
        s = EC_ORDER - s
    return r.to_bytes(64, "big") + s.to_bytes(64, "big")


def ec_verify(pub_bytes: bytes, sig: bytes, data: bytes):
    if len(sig) != EC_SIG:
        raise InvalidSignature
    r, s = int.from_bytes(sig[:64], "big"), int.from_bytes(sig[64:], "big")
    if not (0 < r < EC_ORDER and 0 < s <= EC_ORDER // 2):        # Low-s erzwungen (R8-H3)
        raise InvalidSignature
    ec_load_point(pub_bytes).verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA3_512()))


# ---------------------------------------------------------------- Identitäten und Kontakte

PUB_MAGIC = b"SAPUB3"


_CONFUSABLE = str.maketrans({
    # kyrillisch -> lateinisch
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "п": "n", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h",
    "ӏ": "l", "г": "r", "ь": "b", "ѡ": "w",
    # griechisch -> lateinisch
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ζ": "z", "μ": "u", "ω": "w",
    # Ziffern und Zeichen
    "0": "o", "1": "l", "|": "l", "5": "s", "3": "e", "8": "b",
})


def name_skeleton(name: str) -> str:
    """Vergleichsform gegen Doppelgänger-Namen (z. B. 'Ben' mit kyrillischem 'е')."""
    s = unicodedata.normalize("NFKC", name).casefold().translate(_CONFUSABLE)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return "".join(c for c in s if c.isalnum()).replace("rn", "m")


def _check_name(name: str) -> str:
    name = unicodedata.normalize("NFC", name).strip()
    if not name or len(name) > MAX_NAME or any(unicodedata.category(c)[0] == "C" for c in name):
        raise SigillumError(f"Name ungültig (1–{MAX_NAME} Zeichen, keine Steuerzeichen).")
    scripts = {unicodedata.name(c, "?").split(" ")[0] for c in name if c.isalpha()}
    if len(scripts & {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"}) > 1:
        raise SigillumError("Name mischt Schriften (z. B. lateinisch und kyrillisch) – nicht erlaubt, "
                            "weil sich so Doppelgänger-Namen bauen lassen.")
    return name


class Identity:
    """Basis-Empfangsschlüssel (Hybrid-KEM) + zwei stabile Signaturschlüssel (ECDSA-brainpoolP512r1, ML-DSA-87)."""
    SECRET_LEN = 32 + 32 + 32

    def __init__(self, name, kem_seed: bytes, e_seed: bytes, d_seed: bytes):
        self.name = _check_name(name)
        if len(e_seed) != 32 or len(d_seed) != 32:
            raise SigillumError("Identitätsdatei beschädigt.")
        self.kem = HybridKey(kem_seed)
        self._e_seed, self._d_seed = e_seed, d_seed
        self.e = ec_scalar(hashlib.shake_256(_lp(b"SIGILLUM-v3-ECDSA-expand") + e_seed).digest(96))
        self.d = mldsa.MLDSA87PrivateKey.from_seed_bytes(d_seed)

    @classmethod
    def generate(cls, name: str):
        return cls(name, secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(32))

    def secret_bytes(self) -> bytes:
        return self.kem.seed + self._e_seed + self._d_seed

    @classmethod
    def from_secret(cls, name: str, b: bytes):
        if len(b) != cls.SECRET_LEN:
            raise SigillumError("Identitätsdatei beschädigt.")
        return cls(name, b[:32], b[32:64], b[64:96])

    def sign(self, data: bytes, context: bytes) -> bytes:
        """Hybride Signatur: ECDSA (über context|data) | ML-DSA-87 hedged (pure, mit Kontext)."""
        return ec_sign(self.e, _lp(context) + data) + self.d.sign(data, context)

    def public(self) -> "Contact":
        return Contact(self.name, self.kem.pk, _pt(self.e.public_key()), self.d.public_key().public_bytes_raw())


MLDSA_PK, MLDSA_SIG = 2592, 4627
SIG_LEN = EC_SIG + MLDSA_SIG


def verify_hybrid(contact: "Contact", sig: bytes, data: bytes, context: bytes):
    """Wirft SigillumError, wenn auch nur EINE der beiden Signaturen ungültig ist."""
    try:
        if len(sig) != SIG_LEN:
            raise InvalidSignature
        ec_verify(contact.e_pub, sig[:EC_SIG], _lp(context) + data)
        mldsa.MLDSA87PublicKey.from_public_bytes(contact.d_pub).verify(sig[EC_SIG:], data, context)
    except (InvalidSignature, ValueError):
        raise SigillumError("Signatur ungültig: Nachricht gefälscht oder verändert.") from None


class Contact:
    LENS = (HKEM_PK, EC_PT, MLDSA_PK)

    def __init__(self, name, kem_pk, e_pub, d_pub):
        self.name = _check_name(name)
        self.kem_pk, self.e_pub, self.d_pub = kem_pk, e_pub, d_pub

    def to_bytes(self) -> bytes:
        return PUB_MAGIC + _lp(_nfc(self.name)) + self.kem_pk + self.e_pub + self.d_pub

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) < 10 or b[:6] != PUB_MAGIC:
            raise SigillumError("Keine (oder eine veraltete) öffentliche Schlüsseldatei.")
        (n,) = struct.unpack(">I", b[6:10])
        if n > 4 * MAX_NAME or 10 + n + sum(cls.LENS) != len(b):
            raise SigillumError("Öffentliche Schlüsseldatei beschädigt.")
        p = 10 + n
        parts = []
        for ln in cls.LENS:
            parts.append(b[p:p + ln])
            p += ln
        try:
            name = b[10:10 + n].decode("utf-8")
        except UnicodeDecodeError:
            raise SigillumError("Öffentliche Schlüsseldatei beschädigt.") from None
        c = cls(name, *parts)
        try:
            hkem_check_pk(c.kem_pk)
            ec_load_point(c.e_pub)
            mldsa.MLDSA87PublicKey.from_public_bytes(c.d_pub)
        except (ValueError, SigillumError):
            raise SigillumError("Öffentliche Schlüsseldatei beschädigt.") from None
        if c.to_bytes() != b:                        # nur kanonische Darstellung annehmen
            raise SigillumError("Öffentliche Schlüsseldatei nicht in kanonischer Form.")
        return c

    def fp_raw(self) -> bytes:
        return h3(b"SIGILLUM-FP-v3", self.to_bytes())

    def fp(self) -> str:
        return self.fp_raw().hex()

    def fingerprint(self) -> str:
        """Zum Vergleichen: volle 256 Bit, 16 Gruppen à 4 Zeichen (Befund L6)."""
        h = self.fp_raw().hex().upper()
        return " ".join(h[i:i + 4] for i in range(0, 64, 4))


def normalize_fingerprint(s: str) -> str:
    return re.sub(r"[^0-9A-F]", "", s.upper())


# ---------------------------------------------------------------- Selbsttest beim Start

CRYPTO_SUMMARY = ("AES-256-GCM-SIV · HKDF-SHA-512 · SHA-3 und HMAC-SHA-256 · Argon2id · ML-KEM-1024 + ECDH-brainpoolP512r1 · "
                  "ML-DSA-87 + ECDSA-brainpoolP512r1 (je hybrid, nach BSI TR-02102-1)")


# Bekannt-Antwort-Werte (tests/vectors/hkem_v3.txt; vom unabhängigen Prüfer mit eigener EC-Arithmetik und eigenem
# HKDF in reinem Python nachgerechnet). Erkennen eine abweichend rechnende Bibliothek, z. B. einen anderen OpenSSL-Build.
_KAT_HKEM_SEED = bytes(range(32))
_KAT_HKEM_PK_SHA3 = "ff11a924eda53d6124e40e508f4f2f1bc8dd9c48785cebb7bd41043967d94db6"
_KAT_HKEM_CT = bytes.fromhex(
    "44a67fae64ff91785a8150473fb8cd9a1367b7360b49223aa10786405e4530889a1fd1973e10d8bfaea9832c0313c22b5c54cffca1b760a1bff025129489ad1e067da4df265b33465f0910391fde8c26810a071fe81a625dbcdd5ee7de9d02f80058d8635dd864389355d8dcff9677c1649853cc540d45d97cc169c9b17a04aa441ceb24721876197e78ba0042d8ad7cc54c84125a2d15ed35248f31038ff9ddb3fdbdde7b3f9c31996678304231d9faa278eac758be797551016e1547256b1a7937fe94c6b2afc4c8364b39cce5c973d683565df4df40d77988653b8f161b38c1d331273d86b23daa1be2d63af808528fa7840580c1350c44086e77a5c3ac80a32db6f1e3a533792cb1b1cc1efd9aa0b534f455be6a35d4bbefeef9747ded8fe84e481aa64cec7f7e743810e4e61e090f624319f7ce34b0464bf791c65cfe7b9fa92a46fbf63d3d39daa65df7434bc90f2a73b7d37b3f112a7893c82d95ddacf6b657352a14d398a55873113a3e5667504e28f9d37d41522c427de4d5ffa60ebcb2d9dd1bc671d04f0c9e18d9f5bf420b4d22d1553b778dd19e134f74546381ceb13ed21492451411414bab489dcc848b1bca91bdde195d99e683149277a5b3a5c287cd1511d4565f95131c2c42c57b11e5ccc0a3004767ab98c4ddd1c1da2243e3b602c3a076e1b4d96ffaceb69b34929ef0563de08f7f35b1fd80f22801cff2ad62ec6b17fa35c3bc6ce16d268418b2df74447c859d9b1bdcd81941a18ed6c5a30077df1b96c55806e628170cc59b8b84efe2a8561c150e5b1c6a8dc02a9944b0ed0089128e1cfa9116f7aab7a239e03867077193a90d9ef71ca8b3d8f5ecd1f03385462515d035a5e7bc83cd160ecaafdd6a9a346ff11efa85754658a7e8aa7762d8db0dfcbe71adea5cd96d0647eb674a563f0162ee5c9c0d150279dc30288414631faf6b0093bcb41081340b1bdbeb682be0b5db0229f291886de9025ee9879ee504e4bb0562a765715d2226dddfd6f7d3df82417fc48398fdfb5bbfcec5943971ea164da0a08802ca85a28604d24098418c2f484f7a79d42d9a016d981c162e747192e5c2b1392f504aa8912a3984d1440c94251b0138fbe57785fea1b42e269b2e90e9626437e9e8b1bdb52a1890b0f89c67c3c68e2f4a7d6f8472cc5bd2881c14f8fad73b8772202a09856bef9952b88a2640474515ce0aa804b91e6c02ebdc4c7a713b85691d750534726d990563478c0e7e904d427bf747c4c9a5686ef96f4d740ca8dd5e8d1d480036f0660f5ec4d3497d6c32082736266a455f418735b001c7f1ff866757ca3854b598f13ef061d2a83e55921c2b1952552a891d157f2c4de9431a9678d09a5f93bff3e0915f92f62499c8b14cb10e7291467c9120debdd45ba6fa3954f0bfee2a083a09c4ef8b6a1c23bbff709100c475c57acaade24f8453eb19579741a5b1009385726d70a2e7eae3cdc288d4a2c3d453fc711ff418c7cb8dc86962ee2ec8db00afa8432327279e835a61814aa35bda475d78f7879b9ac5b235c90cb5cab900d438ea975c9831a83c399579062e69ecbe8737b70f00c5960367637ff6086198dcdbe574479c8dfa903d6ecf2979436b591aa71f570a03e35d6a8f2784f222b914b2b8daca91a55e9f56c8c0da2207bccce7ed5620168ac73c695c4987f2760bf40b042358332e374dbfe0ed398ca1767b76a49f1cfdfc37bbcd9da3013e3daaeb53966e752d8a887dbe03c047c0bb84e729c4f46462f5d3ebdea1362a24bf984fa3358242b6eab5b432ee5921961a10c28597ce70dc21c6174c0bc6c08dd1f24900b4d6962c163a6b68c52f68af91bc461789cdd5528573e24a25586962fd6c04732d10cfc267985ff3e1030c04169d9a241acc0aa30efe5cdfafddf60065c0201f3e7f6bb6a4564d525ab2c4d813cc0f0df9b1168e82ca97db5d019ceab5ee2f185c0d48cb3c337d3a76e7396523248872372a91a4f22a7f5a69dea99213c45cc7a2af058f495eaabda4d17a47589e7884c63e69e3acc2e7e56685121f1968ef7eef649b05f4da316dc498db3a6bba4bee30532ca3164cbfb170d1ecffa8ac348ef4639e5959a2b9be342f037d19080e7bfa5af1d1585dcbe1581604982a24394350881fb4a7ffaef31790763774872add878381e2735aa22a38fc59dbc734846e51253a8c6fc511a51ffd95fd81f076d4047dede61ff61dd55a78f129a1cd356adc142232a5d23f4a7cb87fe921903c0113f06ad6a6e327d2bac6b1b1b4fb8b0608796765d15faa07e2c03179d186a1ec6389a8fb286e19d675dd658a64d7dbf33f1423c6c5dbbfb3644296d0d3c4e50a48f34db1e23e999d2d933229f373910f3467ce8a0f53049bcb104c2f9c8349bd22")
_KAT_HKEM_SS = "5e2de37db7feaa193431d5502ff699b1ab576c7069256e1c78c6abbae58ee6bf"
_KAT_IDENT_PUB_SHA3 = "da34d706126bd7d3a50400daff4f9cff66a798f5f797ce0feb9d5dd6e220b758"


def _hkdf_reference(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-512 nach RFC 5869, unabhängig über hmac/hashlib (Gegenprobe zur OpenSSL-HKDF)."""
    import hmac as _hmac
    prk = _hmac.new(b"\x00" * 64, ikm, hashlib.sha512).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out, i = out + t, i + 1
    return out[:length]


def _foreign_vectors() -> None:
    """Prüfwerte, die OHNE OpenSSL/libsodium erzeugt wurden (data/kat_fremd.json): ECDSA-brainpoolP512r1-SHA3-512
    mit eigener Kurvenarithmetik nach RFC 5639, ML-DSA-87 mit dilithium-py (FIPS 204), Argon2id mit argon2-cffi."""
    import json
    with open(os.path.join(_HERE, "data", "kat_fremd.json"), encoding="utf-8") as f:
        v = json.load(f)
    msg = bytes.fromhex(v["msg"])
    ec_verify(bytes.fromhex(v["ecdsa_pub"]), bytes.fromhex(v["ecdsa_sig"]), msg)
    try:
        ec_verify(bytes.fromhex(v["ecdsa_pub"]), bytes.fromhex(v["ecdsa_sig"]), msg + b"!")
        raise ValueError("ECDSA nimmt falsche Nachricht an")
    except InvalidSignature:
        pass
    d = mldsa.MLDSA87PrivateKey.from_seed_bytes(bytes.fromhex(v["mldsa_seed"]))
    pk = d.public_key()
    if hashlib.sha3_256(pk.public_bytes_raw()).hexdigest() != v["mldsa_pk_sha3"]:
        raise ValueError("ML-DSA-Schlüssel")
    pk.verify(bytes.fromhex(v["mldsa_sig"]), msg, bytes.fromhex(v["mldsa_ctx"]))
    a = v["argon2id"]
    if argon2id.kdf(32, bytes.fromhex(a["pw"]), bytes.fromhex(a["salt"]), opslimit=a["ops"],
                    memlimit=a["mem"]).hex() != a["out"]:
        raise ValueError("Argon2id")


def self_test() -> None:
    """Bekannt-Antwort- und Rundlauf-Tests der Primitive (Bibliothek/OpenSSL-Build kann abweichen, z. B. unter
    Windows). Wirft SigillumError, wenn etwas nicht stimmt – die App startet dann nicht."""
    try:
        key, nonce = bytes.fromhex("01" + "00" * 31), bytes.fromhex("03" + "00" * 11)
        if _aead_encrypt(bytes.fromhex("0200000000000000"), b"\x01", nonce, key).hex() != \
                "1de22967237a813291213f267e3b452f02d01ae33e4ec854":                     # RFC 8452 C.2
            raise ValueError("AES-GCM-SIV")
        if hashlib.sha3_256(b"abc").hexdigest() != \
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532":     # FIPS 202
            raise ValueError("SHA3")
        if hkdf(b"ikm" * 20, b"info") != _hkdf_reference(b"ikm" * 20, b"info", 32):
            raise ValueError("HKDF")
        k = HybridKey(_KAT_HKEM_SEED)                       # ML-KEM-1024-KeyGen, ECDH, Kombinierer
        if hashlib.sha3_256(k.pk).hexdigest() != _KAT_HKEM_PK_SHA3 or k.decap(_KAT_HKEM_CT).hex() != _KAT_HKEM_SS:
            raise ValueError("Hybrid-KEM")
        ss, ct = hkem_encap(k.pk)
        if k.decap(ct) != ss or HybridKey(b"\x01" * 32).decap(ct) == ss:
            raise ValueError("Hybrid-KEM")
        ident = Identity("Selbsttest", bytes(32), b"\x01" * 32, b"\x02" * 32)      # ECDSA-/ML-DSA-KeyGen
        if hashlib.sha3_256(ident.public().to_bytes()).hexdigest() != _KAT_IDENT_PUB_SHA3:
            raise ValueError("Signatur-Schlüssel")
        _foreign_vectors()                                   # Befund R12-H4: Prüfwerte fremder Implementierungen
        sig = ident.sign(b"x", b"t")
        verify_hybrid(ident.public(), sig, b"x", b"t")
        for bad in ((sig, b"y"), (sig[:-1] + bytes([sig[-1] ^ 1]), b"x"), (bytes([sig[0] ^ 1]) + sig[1:], b"x")):
            try:
                verify_hybrid(ident.public(), bad[0], bad[1], b"t")
            except SigillumError:
                continue
            raise ValueError("Signatur")
    except Exception as e:
        raise SigillumError(f"Selbsttest der Kryptografie fehlgeschlagen ({e}). Bitte installieren.bat erneut "
                            "ausführen; die App startet so nicht.") from None
