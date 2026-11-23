"""Shamir-Secret-Sharing (2 von 3) über dem Primkörper F_p nach BSI TR-02102-1, Kapitel 7.

  Schlüsseldatei (r = 352 Bit):  p = 2^521 - 1   (Mersenne-Primzahl)
  Notfall-Paket  (r = 736 Bit):  p = 2^1279 - 1  (Mersenne-Primzahl)
  Jeweils p >= max(2^r, n+1); Primalität wird im Test per Lucas-Lehmer nachgewiesen.
  Tab. 7.1: a0 = Geheimnis als Zahl (Big-Endian statt Summe k_i·2^i – gleichwertige, eindeutige Kodierung), a1..a(k-1) gleichverteilt aus {0..p-1}, Teil i = f(i) mod p.
  Tab. 7.2: a0 = Summe c_j * K_j mit c_j = Produkt x_l / (x_l - x_j) mod p.
Weniger Teile als die Schwelle verraten informationstheoretisch nichts (Bem. 7.2) – für das Notfall-Paket siehe
den Hinweis zum Bindewert in notfall.py.
"""
import secrets

from .core import h3

SHARE_MAGIC = b"SASHP1"                      # Schlüsseldatei-Backup
SECRET_LEN = 44                              # genau eine Schlüsseldatei
PACKAGE_MAGIC = b"SASHP3"                    # Notfall-Paket (siehe notfall.py)
PACKAGE_LEN = 44 + 16 + 32                   # Schlüsseldatei | code_id | Notfall-Code
EXTRA = {SHARE_MAGIC: 0, PACKAGE_MAGIC: 32}  # offener Zusatz je Teil (Notfall-Paket: Bindewert)
MERSENNE = {SHARE_MAGIC: 521, PACKAGE_MAGIC: 1279}
PRIME = {m: 2 ** e - 1 for m, e in MERSENNE.items()}
Y_LEN = {m: (e + 7) // 8 for m, e in MERSENNE.items()}       # 66 bzw. 160 Byte
FORMATS = {SHARE_MAGIC: SECRET_LEN, PACKAGE_MAGIC: PACKAGE_LEN}
HDR = 6 + 4 + 3
CHK = 4


def _chk(body: bytes) -> bytes:
    return h3(b"SIGILLUM-SHARE-CHK", body, CHK)


def share_len(magic: bytes) -> int:
    return HDR + Y_LEN[magic] + EXTRA[magic] + CHK


def split(secret: bytes, n: int = 3, k: int = 2, magic: bytes = SHARE_MAGIC, extra: bytes = b"") -> list[bytes]:
    if not 2 <= k <= n <= 255 or magic not in FORMATS or len(secret) != FORMATS[magic] or len(extra) != EXTRA[magic]:
        raise ValueError("Ungültige Parameter")
    P = PRIME[magic]
    a0 = int.from_bytes(secret, "big")
    if not (8 * len(secret) < MERSENNE[magic] and a0 < P and n < P):
        raise ValueError("Ungültige Parameter")
    coeffs = [a0] + [secrets.randbelow(P) for _ in range(k - 1)]      # gleichverteilt aus {0..p-1}
    set_id = secrets.token_bytes(4)
    out = []
    for x in range(1, n + 1):
        y = 0
        for c in reversed(coeffs):           # Horner
            y = (y * x + c) % P
        body = magic + set_id + bytes([x, k, n]) + y.to_bytes(Y_LEN[magic], "big") + extra
        out.append(body + _chk(body))
    return out


def parse(share: bytes) -> dict:
    magic = share[:6]
    if magic not in FORMATS or len(share) != share_len(magic):
        raise ValueError("Kein gültiger Backup-Teil (oder aus einer älteren App-Version).")
    body, chk = share[:-CHK], share[-CHK:]
    if _chk(body) != chk:
        raise ValueError("Backup-Teil beschädigt (Prüfsumme falsch).")
    x, k, n = body[10], body[11], body[12]
    y = int.from_bytes(body[HDR:HDR + Y_LEN[magic]], "big")
    if not (1 <= x <= n and 2 <= k <= n) or y >= PRIME[magic]:
        raise ValueError("Backup-Teil ungültig.")
    return {"magic": magic, "set": body[6:10], "x": x, "k": k, "n": n, "y": y, "extra": body[HDR + Y_LEN[magic]:]}


def combine(shares: list[bytes]) -> bytes:
    if not shares:
        raise ValueError("Keine Teile angegeben.")
    ps = [parse(s) for s in shares]
    if len({p["magic"] for p in ps}) != 1:
        raise ValueError("Die Teile gehören zu verschiedenen Backup-Arten.")
    if len({p["set"] for p in ps}) != 1:
        raise ValueError("Die Teile gehören nicht zum selben Backup.")
    if len({(p["k"], p["n"]) for p in ps}) != 1:
        raise ValueError("Die Teile widersprechen sich.")
    k = ps[0]["k"]
    xs = [p["x"] for p in ps]
    if len(set(xs)) != len(xs):
        raise ValueError("Derselbe Teil wurde doppelt angegeben.")
    if len(ps) < k:
        raise ValueError(f"Es werden mindestens {k} verschiedene Teile benötigt.")
    ps, xs = ps[:k], xs[:k]
    P = PRIME[ps[0]["magic"]]
    a0 = 0
    for j, pj in enumerate(ps):
        c = 1
        for m, xm in enumerate(xs):
            if m != j:
                c = c * xm * pow(xm - xs[j], -1, P) % P
        a0 = (a0 + c * pj["y"]) % P
    size = FORMATS[ps[0]["magic"]]
    if a0 >> (8 * size):
        raise ValueError("Die Teile passen nicht zusammen (falsch abgetippt oder verfälscht).")
    return a0.to_bytes(size, "big")


def kind(shares: list[bytes]) -> bytes:
    """Art der Teile (SHARE_MAGIC = Schlüsseldatei, PACKAGE_MAGIC = Notfall-Paket); setzt gültige Teile voraus."""
    return parse(shares[0])["magic"]


def combine_keyfile(shares: list[bytes]) -> tuple[bytes, list[int]]:
    """Befund R8-H4: Schlüsseldatei aus 2 oder 3 Teilen, robust gegen EINEN verfälschten oder vertippten Teil.

    Jedes Paar wird zusammengesetzt und das Ergebnis über Kennung und Prüfsumme der Schlüsseldatei geprüft.
    Bei drei Teilen müssen alle drei auf DERSELBEN Geraden liegen (informationstheoretische Gegenprobe,
    TR-02102-1 Bem. 7.1); liegt ein Teil daneben, wird das stimmige Paar benutzt und der Teil gemeldet.
    Es wird bewusst KEIN offener Hash des Geheimnisses in die Teile geschrieben: ein einzelner Teil bleibt
    informationstheoretisch ohne Aussage über die Schlüsseldatei.
    Nicht lesbare Teile (Prüfsumme/Format) werden übersprungen, wenn zwei gültige bleiben.
    Rückgabe: (Schlüsseldatei, Liste der 0-basierten Indizes verdächtiger oder unlesbarer Teile)."""
    import itertools
    from .core import SigillumError, read_keyfile
    if not shares:
        raise ValueError("Keine Teile angegeben.")
    unreadable, ok = [], []
    for i, sh in enumerate(shares):                      # unlesbare Teile (Prüfsumme, Format) überspringen
        try:
            parse(sh)
            ok.append(i)
        except ValueError:
            unreadable.append(i)
    if unreadable:
        if len(ok) < 2:
            raise ValueError("Teil " + ", ".join(str(i + 1) for i in unreadable) + " der Eingabe ist nicht lesbar "
                             "(falsch abgetippt oder beschädigt), und es bleiben keine zwei gültigen Teile.")
        kf, suspect = combine_keyfile([shares[i] for i in ok])
        return kf, sorted(unreadable + [ok[i] for i in suspect])
    ps = [parse(s) for s in shares]
    if any(p["magic"] != SHARE_MAGIC for p in ps):
        raise ValueError("Das sind keine Teile eines Schlüsseldatei-Backups.")
    if len({p["set"] for p in ps}) != 1:
        raise ValueError("Die Teile gehören nicht zum selben Backup.")
    if len({p["x"] for p in ps}) != len(ps):
        raise ValueError("Derselbe Teil wurde doppelt angegeben.")
    if len({(p["k"], p["n"]) for p in ps}) != 1 or ps[0]["k"] != 2:
        raise ValueError("Die Teile widersprechen sich (nur 2-aus-n-Backups werden unterstützt).")
    if len(ps) < ps[0]["k"]:
        raise ValueError(f"Es werden mindestens {ps[0]['k']} verschiedene Teile benötigt.")
    results = {}
    for i, j in itertools.combinations(range(len(shares)), 2):
        try:
            kf = combine([shares[i], shares[j]])
            read_keyfile(kf)
        except (ValueError, SigillumError):
            continue
        results.setdefault(kf, set()).update((i, j))
    if len(results) == 1:
        (kf, used), = results.items()
        if len(used) == len(shares):
            # Zwei stimmige Paare mit gemeinsamem Teil und gleichem a0 liegen auf derselben Geraden -> alle stimmig
            return kf, []
        return kf, sorted(set(range(len(shares))) - used)
    if len(shares) == 2:
        raise ValueError("Die beiden Teile passen nicht zusammen – einer ist falsch abgetippt oder verfälscht. "
                         "Den dritten Teil dazunehmen.")
    if not results:
        raise ValueError("Kein Paar der Teile ergibt eine gültige Schlüsseldatei – mindestens zwei Teile sind falsch "
                         "oder verfälscht.")
    raise ValueError("Die Teile ergeben widersprüchliche Schlüsseldateien – mindestens ein Teil ist verfälscht. "
                     "Nichts wiederhergestellt.")
