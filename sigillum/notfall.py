"""Notfall-Paket (Konzept-Variante A): Shamir 2 aus 3 (Primkörper, TR-02102-1 Kap. 7) über Schlüsseldatei +
Notfall-Code der Identität.

Teil = shamir.PACKAGE_MAGIC ("SASHP3") | satz | x | k | n | y (160 Byte) | Bindewert (32 Byte, offen) | Prüfsumme
Bindewert = SHA3-256(Zweck "SIGILLUM-SHRC" | satz | Schlüsseldatei | code_id | code) – in JEDEM Teil gleich.

Ein einzelner Teil verrät nichts über das Geheimnis (Shamir). Der offene Bindewert ist ein SHA3-Hash über 512 Bit
geheimen Zufall (32 Byte Schlüsseldatei-Geheimnis + 32 Byte Notfall-Code; code_id steht offen im Dateikopf) – ein
Teil samt Bindewert ist damit nicht mehr informationstheoretisch, aber rechnerisch mit 2^512 Aufwand geschützt.
Wer EINEN Ort manipuliert, kann zwar einen Teil fälschen, aber das Ergebnis passt dann nicht zum Bindewert der
anderen Teile: Die App erkennt das und findet bei drei Teilen das unverfälschte Paar (Befund R4-5).
"""
import hmac
import itertools

from . import core, shamir
from .i18n import _

PARTS, NEEDED = 3, 2
SECRET_LEN, BIND_LEN = 44 + 16 + 32, 32


def _bind(set_id: bytes, secret: bytes) -> bytes:
    return core.h3(b"SIGILLUM-SHRC", set_id + secret, BIND_LEN)


def build(keyfile: bytes, code_id: bytes, code: bytes) -> list[bytes]:
    core.read_keyfile(keyfile)
    if len(code_id) != 16 or len(code) != 32:
        raise core.SigillumError(_("Interner Fehler: Notfall-Code ungültig."))
    secret = keyfile + code_id + code
    # Der Bindewert hängt vom Satz ab, den split() erst würfelt: zweistufig (Satz vorab festlegen geht nicht),
    # daher zuerst teilen, dann Bindewert für den gewürfelten Satz einsetzen und Prüfsumme neu bilden.
    raw = shamir.split(secret, PARTS, NEEDED, shamir.PACKAGE_MAGIC, bytes(BIND_LEN))
    out = []
    for part in raw:
        body = part[:-shamir.CHK]
        set_id = body[6:10]
        body = body[:-BIND_LEN] + _bind(set_id, secret)
        out.append(body + shamir._chk(body))
    return out


def _combine_pair(a: bytes, b: bytes):
    pa, pb = shamir.parse(a), shamir.parse(b)
    if pa["extra"] != pb["extra"]:
        return None
    try:
        secret = shamir.combine([a, b])
    except ValueError:
        return None
    if not hmac.compare_digest(_bind(pa["set"], secret), pa["extra"]):
        return None
    return secret


def open_parts(parts: list[bytes]) -> tuple[bytes, bytes, bytes]:
    """-> (Schlüsseldatei, code_id, code). Prüft den Bindewert; bei drei Teilen wird ein verfälschter Teil
    erkannt und das unverfälschte Paar benutzt. Wirft ValueError/SigillumError."""
    if not parts:
        raise ValueError(_("Keine Teile angegeben."))
    ps = [shamir.parse(p) for p in parts]
    if any(p["magic"] != shamir.PACKAGE_MAGIC for p in ps):
        if all(p["magic"] == shamir.SHARE_MAGIC for p in ps):
            raise ValueError(_("Das sind Teile eines normalen Schlüsseldatei-Backups, kein Notfall-Paket."))
        raise ValueError(_("Teile verschiedener Arten oder eines veralteten Notfall-Pakets – bitte die aktuellen "
                           "Notfall-Papiere verwenden."))
    if len(ps) < NEEDED:
        raise ValueError(_("Es werden mindestens {0} verschiedene Teile benötigt.").format(NEEDED))
    if len({p["x"] for p in ps}) != len(ps):
        raise ValueError(_("Derselbe Teil wurde doppelt angegeben."))
    if len({p["set"] for p in ps}) != 1:
        raise ValueError(_("Die Teile gehören nicht zum selben Notfall-Paket."))
    bad = set()
    for i, j in itertools.combinations(range(len(parts)), 2):
        secret = _combine_pair(parts[i], parts[j])
        if secret is not None:
            keyfile, code_id, code = secret[:44], secret[44:60], secret[60:92]
            core.read_keyfile(keyfile)
            return keyfile, code_id, code
        bad.update((i, j))
    if len(parts) == 2:
        raise ValueError(_("Die beiden Teile passen nicht zusammen – einer ist falsch abgetippt oder verfälscht. "
                           "Den dritten Teil dazunehmen."))
    raise ValueError(_("Kein Paar der Teile ergibt ein gültiges Notfall-Paket – mindestens zwei Teile sind falsch "
                       "oder verfälscht."))


def verify_all_pairs(parts: list[bytes], keyfile: bytes, code_id: bytes, code: bytes) -> bool:
    """Kontrolle nach dem Erzeugen: jedes Paar muss genau das Paket ergeben."""
    want = keyfile + code_id + code
    for a, b in itertools.combinations(parts, 2):
        if _combine_pair(a, b) != want:
            return False
    return True
