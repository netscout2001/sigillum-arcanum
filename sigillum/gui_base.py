"""Sigillum Arcanum – Bausteine der Oberfläche: Dateien, Einstellungen, Design, Plattform-Erkennung."""
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import sys
import tkinter as tk
from tkinter import ttk

from . import core, handmode, ratchet
from . import i18n
from .i18n import _, num

HERE = os.path.dirname(os.path.abspath(__file__))
FONT_FAMILY = "Sigillum Arcanum"
APP_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/.config"), "SigillumArcanum")
CLOUD_HINTS = ("onedrive", "dropbox", "google drive", "googledrive", "my drive", "meine ablage", "icloud", "nextcloud",
               "pcloud", "megasync", "box sync", "seafile", "sync.com", "tresorit")
LOCK_CHOICES = (5, 10, 15, 30)          # Minuten ohne Bedienung bis zur automatischen Sperre
LOCK_DEFAULT = 10
QUICK_TRIES = 3                         # 3 Versuche wie TR-02102-1 Tab. 6.2 (nur in der App durchgesetzt, Bem. 6.4)
ERRORS = (core.SigillumError, handmode.HandError, ValueError, OSError)


# ---------------------------------------------------------------- Dateien

def write_atomic(path, data: bytes):
    """Erst in eine temporäre Datei, dann ersetzen – nie halb geschriebene Dateien."""
    tmp = f"{path}.{secrets.token_hex(4)}.tmp"
    try:
        with open(tmp, "xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def write_new(path, data: bytes):
    """Neue Datei anlegen; eine vorhandene wird NIE überschrieben."""
    with open(path, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def same_drive(a: str, b: str) -> bool:
    """Gleiches Laufwerk/Gerät (USB-Stick, Partition)?"""
    try:
        if sys.platform == "win32":
            return os.path.splitdrive(os.path.realpath(a))[0].lower() == os.path.splitdrive(os.path.realpath(b))[0].lower()
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return True


def same_folder(a: str, b: str) -> bool:
    try:
        return (os.path.normcase(os.path.dirname(os.path.realpath(a)))
                == os.path.normcase(os.path.dirname(os.path.realpath(b))))
    except OSError:
        return False


def wipe(paths) -> list:
    """Überschreibt Dateien mit Zufall und löscht sie. Gibt die nicht löschbaren zurück.
    (Auf SSDs ist Überschreiben nicht garantiert wirksam – darum BitLocker.)"""
    left = []
    for p in paths:
        try:
            n = os.path.getsize(p)
            with open(p, "r+b") as f:
                f.write(secrets.token_bytes(n))
                f.flush()
                os.fsync(f.fileno())
            os.remove(p)
        except FileNotFoundError:
            pass
        except OSError:
            left.append(p)
    return left


def read_file(path, limit=ratchet.MAX_VAULT) -> bytes:
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise core.SigillumError(_("Datei zu groß."))
    return data


def read_keyfile_path(path, what):
    if not path:
        raise core.SigillumError(_("Bitte die Schlüsseldatei für {0} wählen.").format(what))
    try:
        kf = read_file(path, 1024)
    except OSError:
        raise core.SigillumError(_("Schlüsseldatei für {0} nicht lesbar.").format(what)) from None
    core.read_keyfile(kf)
    return kf


# ---------------------------------------------------------------- Plattform

def load_private_font():
    """Lädt den Font nur für diesen Prozess (Windows). Unter Linux/macOS muss er installiert sein."""
    if sys.platform == "win32":
        import ctypes
        for style in ("Regular", "Bold"):
            ctypes.windll.gdi32.AddFontResourceExW(os.path.join(HERE, "fonts", f"SigillumArcanum-{style}.ttf"), 0x10, 0)


def clipboard_history_enabled():
    if sys.platform != "win32":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard") as k:
            return winreg.QueryValueEx(k, "EnableClipboardHistory")[0] == 1
    except OSError:
        return False


def cloud_roots() -> list:
    """Synchronisierte Ordner laut Windows-Umgebung (OneDrive setzt diese Variablen)."""
    out = []
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        v = os.environ.get(var)
        if v:
            out.append(os.path.normcase(os.path.realpath(v)))
    return out


def is_cloud(path: str) -> bool:
    """Liegt der Pfad (vermutlich) in einem synchronisierten Cloud-Ordner?"""
    if not path:
        return False
    low = path.lower()
    if any(h in low for h in CLOUD_HINTS):
        return True
    try:
        rp = os.path.normcase(os.path.realpath(path))
    except OSError:
        return False
    return any(rp == r or rp.startswith(r + os.sep) for r in cloud_roots())


def removable_drives() -> list:
    """Wechseldatenträger (USB-Sticks) – nur unter Windows erkennbar, sonst leer."""
    if sys.platform != "win32":
        return []
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        out = []
        for i, letter in enumerate(string.ascii_uppercase):
            if mask & (1 << i):
                root = f"{letter}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:      # DRIVE_REMOVABLE
                    out.append(root)
        return out
    except (OSError, AttributeError):
        return []


def is_removable(path: str) -> bool:
    if sys.platform != "win32" or not path:
        return False
    drive = os.path.splitdrive(os.path.realpath(path))[0].upper()
    return any(r.upper().startswith(drive) for r in removable_drives()) if drive else False


def workstation_locked() -> bool:
    """Windows: Ist der Bildschirm gesperrt? (Das Eingabe-Desktop lässt sich dann nicht öffnen.)
    Unbekannt/andere Systeme -> False. Nur ein Zusatz zur Sperre nach Zeit."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        user32 = ctypes.windll.user32
        h = user32.OpenInputDesktop(0, False, 0x0100)              # DESKTOP_SWITCHDESKTOP
        if not h:
            return True
        user32.CloseDesktop(h)
        return False
    except (OSError, AttributeError):
        return False


def default_identity_dir() -> str:
    """Lokaler, nicht synchronisierter Ordner (Windows: %LOCALAPPDATA%)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "SigillumArcanum", "Identitaet")


# ---------------------------------------------------------------- kleine Bausteine (auch von Tests benutzt)

def gap_text(r) -> str:
    """Fehlende Nachrichten kurz beschreiben (Befund R2-3: nie eine riesige Liste anzeigen)."""
    n, nums = r.get("gap_count", len(r["gap"])), r["gap"]
    if n <= len(nums):
        return _("Nachricht Nr. {0}").format(', '.join(map(str, nums)))
    return _("{0} Nachrichten (Nr. {1} bis {2})").format(num(n), num(nums[0]), num(nums[0] + n - 1))


def scrolled_text(parent, height=6, font=None, readonly=False, app=None):
    frame = ttk.Frame(parent, style="Card.TFrame")
    t = tk.Text(frame, height=height, wrap="char", font=font, undo=False, padx=6, pady=4)   # L3: kein Rückgängig
    sb = ttk.Scrollbar(frame, command=t.yview)
    t.configure(yscrollcommand=sb.set)
    t.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    if readonly:
        t.configure(state="disabled")
    if app is not None:
        app.register_text(t)
    return frame, t


def set_text(t, s):
    ro = str(t.cget("state")) == "disabled"
    t.configure(state="normal")
    t.delete("1.0", "end")
    t.insert("1.0", s)
    t.edit_reset()
    if ro:
        t.configure(state="disabled")


def get_text(t):
    return t.get("1.0", "end-1c")


# ---------------------------------------------------------------- Lokale Einstellungen (nicht geheim)

class Config:
    """Gerätekennung, Kennungen benutzter Schlüsseldateien (Befund H1), gesehene gemeinsame Nachrichten,
    Oberfläche (Design, Sperrzeit, Schnell-Entsperren), zuletzt benutzte PFADE (nie Geheimnisse) und erledigte
    Einrichtungsschritte. Schlüsseldatei-/Identitäts-Kennungen nur als gerätespezifische HMAC-Werte."""

    LISTS = ("identity_kf", "shared_kf", "seen", "fido_ids", "backup_kf", "exported")

    def __init__(self):
        os.makedirs(APP_DIR, exist_ok=True)
        self.path = os.path.join(APP_DIR, "einstellungen.json")
        try:
            with open(self.path, encoding="utf-8") as f:
                self.d = json.load(f)
            if not isinstance(self.d, dict):
                raise ValueError
        except (OSError, ValueError):
            self.d = {}
        changed = False
        if not re.fullmatch(r"[0-9a-f]{32}", str(self.d.get("device", ""))):
            self.d["device"] = secrets.token_hex(16)
            changed = True
        for k in self.LISTS:
            if not isinstance(self.d.get(k), list) or not all(isinstance(x, str) for x in self.d[k]):
                self.d[k] = []
                changed = True
        if self.d.get("kf_tags") != 1:
            self.d["kf_tags"] = 1
            changed = True
        ui = self.d.get("ui")
        good = (isinstance(ui, dict) and ui.get("theme") in ("light", "dark") and ui.get("lock_min") in LOCK_CHOICES
                and isinstance(ui.get("quick"), bool))
        if not good:
            keep = ui.get("lang") if isinstance(ui, dict) else None
            self.d["ui"] = {"theme": "light", "lock_min": LOCK_DEFAULT, "quick": False, "lang": keep}
            changed = True
        if self.d["ui"].get("lang") not in i18n.LANGS:      # erster Start: erkannte Sprache festhalten
            self.d["ui"]["lang"] = i18n.LANG
            changed = True
        for k in ("last_id", "last_ikf"):
            if not isinstance(self.d.get(k, ""), str):
                self.d[k] = ""
                changed = True
        gens = self.d.get("gens")
        if not isinstance(gens, dict) or not all(isinstance(k, str) and type(v) is int and v >= 0
                                                 for k, v in gens.items()):
            self.d["gens"] = {}
            changed = True
        if changed:
            self.save()

    def save(self):
        write_atomic(self.path, json.dumps(self.d, indent=1).encode("utf-8"))

    @property
    def device(self) -> bytes:
        return bytes.fromhex(self.d["device"])

    def _tag(self, label: bytes, data: bytes) -> str:
        return hmac.new(self.device, label + data, hashlib.sha256).hexdigest()

    def kf_tag(self, digest: str) -> str:
        return self._tag(b"SIGILLUM-KFTAG", bytes.fromhex(digest))

    def channel_tag(self, digest: str) -> bytes:
        """Absenderkennung je gemeinsamem Schlüssel: in verschiedenen Kanälen nicht als dasselbe Gerät erkennbar."""
        return bytes.fromhex(self._tag(b"SIGILLUM-CHAN", bytes.fromhex(digest)))[:16]

    def set_fido(self, fp_raw: bytes, on: bool):
        """Merkt sich gerätespezifisch, welche Identität einen YubiKey hat (Warnung bei alten Kopien ohne Key)."""
        t = self._tag(b"SIGILLUM-FIDO", fp_raw)
        if on and t not in self.d["fido_ids"]:
            self.d["fido_ids"].append(t)
            self.save()
        elif not on and t in self.d["fido_ids"]:
            self.d["fido_ids"].remove(t)
            self.save()

    def get_gen(self, fp_raw: bytes) -> int:
        """Befund R12-N4: höchste auf DIESEM Rechner gesehene Generation der Identitätsdatei."""
        return self.d["gens"].get(self._tag(b"SIGILLUM-GEN", fp_raw), 0)

    def set_gen(self, fp_raw: bytes, gen: int, only_up: bool = True):
        t = self._tag(b"SIGILLUM-GEN", fp_raw)
        if not only_up or gen > self.d["gens"].get(t, 0):
            self.d["gens"][t] = gen
            self.save()

    def had_fido(self, fp_raw: bytes) -> bool:
        return self._tag(b"SIGILLUM-FIDO", fp_raw) in self.d["fido_ids"]

    def has(self, key, digest) -> bool:
        return self.kf_tag(digest) in self.d[key]

    def note(self, key, digest):
        t = self.kf_tag(digest)
        if t not in self.d[key]:
            self.d[key].append(t)
            self.save()

    def note_exported(self, fp_raw: bytes):
        t = self._tag(b"SIGILLUM-EXPORTED", fp_raw)
        if t not in self.d["exported"]:
            self.d["exported"].append(t)
            self.save()

    def was_exported(self, fp_raw: bytes) -> bool:
        return self._tag(b"SIGILLUM-EXPORTED", fp_raw) in self.d["exported"]

    def seen_before(self, msgid: bytes) -> bool:
        h = core.h3(b"SIGILLUM-SEEN-SHARED", msgid, 16).hex()
        if h in self.d["seen"]:
            return True
        self.d["seen"] = (self.d["seen"] + [h])[-5000:]
        self.save()
        return False

    def ui(self, key):
        return self.d["ui"][key]

    def set_ui(self, key, value):
        self.d["ui"][key] = value
        self.save()

    def set_paths(self, id_path=None, ikf_path=None):
        if id_path is not None:
            self.d["last_id"] = id_path
        if ikf_path is not None:
            self.d["last_ikf"] = ikf_path
        self.save()


# ---------------------------------------------------------------- Design (Kontrast >= 4,5:1 nach WCAG AA, geprüft)

PALETTES = {
    "light": {
        "bg": "#F3F4F6", "surface": "#FFFFFF", "text": "#111827", "muted": "#4B5563", "border": "#9CA3AF",
        "side": "#1F2937", "side_text": "#FFFFFF", "side_active": "#1D4ED8", "side_hover": "#374151",
        "primary": "#1D4ED8", "primary_text": "#FFFFFF", "primary_hover": "#1E40AF",
        "danger": "#B91C1C", "danger_text": "#FFFFFF", "danger_fg": "#B91C1C",
        "ok": "#166534", "warn": "#9A3412", "input": "#FFFFFF", "select": "#BFDBFE",
        "badge_locked": "#B91C1C", "badge_open": "#166534", "badge_text": "#FFFFFF",
    },
    "dark": {
        "bg": "#0F141A", "surface": "#1A2129", "text": "#E5E7EB", "muted": "#B6BDC7", "border": "#6B7280",
        "side": "#0A0E13", "side_text": "#F9FAFB", "side_active": "#1D4ED8", "side_hover": "#1F2937",
        "primary": "#1D4ED8", "primary_text": "#FFFFFF", "primary_hover": "#1E40AF",
        "danger": "#B91C1C", "danger_text": "#FFFFFF", "danger_fg": "#FCA5A5",
        "ok": "#4ADE80", "warn": "#FDBA74", "input": "#0F141A", "select": "#1E3A8A",
        "badge_locked": "#B91C1C", "badge_open": "#166534", "badge_text": "#FFFFFF",
    },
}
# Farbpaare (Vordergrund, Hintergrund), die tatsächlich vorkommen – im Test gegen 4,5:1 geprüft
CONTRAST_PAIRS = (("text", "bg"), ("text", "surface"), ("muted", "surface"), ("muted", "bg"), ("side_text", "side"),
                  ("side_text", "side_active"), ("side_text", "side_hover"), ("primary_text", "primary"),
                  ("primary_text", "primary_hover"), ("danger_text", "danger"), ("ok", "surface"), ("ok", "bg"),
                  ("warn", "surface"), ("warn", "bg"), ("badge_text", "badge_locked"), ("badge_text", "badge_open"),
                  ("text", "input"), ("text", "select"), ("danger_fg", "surface"), ("danger_fg", "bg"))


def _lum(hexcol: str) -> float:
    c = [int(hexcol[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def contrast(fg: str, bg: str) -> float:
    a, b = sorted((_lum(fg), _lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


FONT = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"


def apply_theme(root: tk.Tk, name: str) -> dict:
    """ttk-Design 'clam' mit eigenen Farben. Gibt die Palette zurück (für tk.Text-Felder)."""
    p = PALETTES[name]
    st = ttk.Style(root)
    st.theme_use("clam")
    root.configure(background=p["bg"])
    base = (FONT, 10)
    st.configure(".", background=p["bg"], foreground=p["text"], font=base, bordercolor=p["border"],
                 fieldbackground=p["input"], troughcolor=p["bg"], lightcolor=p["bg"], darkcolor=p["bg"],
                 selectbackground=p["select"], selectforeground=p["text"], insertcolor=p["text"])
    st.configure("TFrame", background=p["bg"])
    st.configure("Card.TFrame", background=p["surface"], relief="solid", borderwidth=1)
    st.configure("Side.TFrame", background=p["side"])
    st.configure("Inner.TFrame", background=p["surface"])
    st.configure("Head.TFrame", background=p["surface"])
    for name_, bg in (("TLabel", p["bg"]), ("Card.TLabel", p["surface"])):
        st.configure(name_, background=bg, foreground=p["text"])
    st.configure("Title.TLabel", background=p["bg"], foreground=p["text"], font=(FONT, 15, "bold"))
    st.configure("AppTitle.TLabel", background=p["surface"], foreground=p["text"], font=(FONT, 13, "bold"))
    st.configure("Head.TLabel", background=p["surface"], foreground=p["text"], font=(FONT, 11, "bold"))
    st.configure("HeadBg.TLabel", background=p["bg"], foreground=p["text"], font=(FONT, 11, "bold"))
    st.configure("Muted.TLabel", background=p["surface"], foreground=p["muted"])
    st.configure("MutedBg.TLabel", background=p["bg"], foreground=p["muted"])
    st.configure("HeaderMuted.TLabel", background=p["surface"], foreground=p["muted"])
    st.configure("Warn.TLabel", background=p["surface"], foreground=p["warn"], font=(FONT, 10, "bold"))
    st.configure("WarnBg.TLabel", background=p["bg"], foreground=p["warn"], font=(FONT, 10, "bold"))
    st.configure("Ok.TLabel", background=p["surface"], foreground=p["ok"], font=(FONT, 10, "bold"))
    st.configure("Locked.TLabel", background=p["badge_locked"], foreground=p["badge_text"], font=(FONT, 10, "bold"),
                 padding=(10, 4))
    st.configure("Open.TLabel", background=p["badge_open"], foreground=p["badge_text"], font=(FONT, 10, "bold"),
                 padding=(10, 4))
    st.configure("Status.TLabel", background=p["surface"], foreground=p["text"], padding=(10, 4))
    st.configure("TButton", background=p["surface"], foreground=p["text"], padding=(10, 5), borderwidth=1)
    st.map("TButton", background=[("active", p["select"]), ("pressed", p["select"])],
           foreground=[("disabled", p["muted"])])
    st.configure("Primary.TButton", background=p["primary"], foreground=p["primary_text"], font=(FONT, 10, "bold"),
                 padding=(14, 6))
    st.map("Primary.TButton", background=[("active", p["primary_hover"]), ("pressed", p["primary_hover"])],
           foreground=[("active", p["primary_text"])])
    st.configure("Danger.TButton", background=p["surface"], foreground=p["danger_fg"], bordercolor=p["danger_fg"])
    st.map("Danger.TButton", background=[("active", p["danger"])], foreground=[("active", p["danger_text"])])
    st.configure("Nav.TButton", background=p["side"], foreground=p["side_text"], font=(FONT, 11), anchor="w",
                 padding=(16, 10), borderwidth=0)
    st.map("Nav.TButton", background=[("active", p["side_hover"])], foreground=[("active", p["side_text"])])
    st.configure("NavActive.TButton", background=p["side_active"], foreground=p["side_text"], font=(FONT, 11, "bold"),
                 anchor="w", padding=(16, 10), borderwidth=0)
    st.map("NavActive.TButton", background=[("active", p["side_active"])], foreground=[("active", p["side_text"])])
    st.configure("SideTitle.TLabel", background=p["side"], foreground=p["side_text"], font=(FONT, 13, "bold"),
                 padding=(16, 14))
    for w in ("TCheckbutton", "TRadiobutton"):
        st.configure(w, background=p["bg"], foreground=p["text"])
        st.configure("Card." + w, background=p["surface"], foreground=p["text"])
        st.map("Card." + w, background=[("active", p["surface"])])
        st.map(w, background=[("active", p["bg"])])
    for w in ("TCheckbutton", "TRadiobutton", "Card.TCheckbutton", "Card.TRadiobutton"):
        st.configure(w, indicatorbackground=p["input"], indicatorforeground=p["text"], upperbordercolor=p["border"],
                     lowerbordercolor=p["border"])
        st.map(w, indicatorbackground=[("selected", p["primary"]), ("active", p["select"])],
               indicatorforeground=[("selected", p["primary_text"])])
    st.configure("TScrollbar", background=p["surface"], troughcolor=p["bg"], arrowcolor=p["text"],
                 bordercolor=p["border"])
    st.map("TScrollbar", background=[("active", p["select"])])
    st.configure("TProgressbar", background=p["primary"], troughcolor=p["bg"])
    st.configure("TEntry", fieldbackground=p["input"], foreground=p["text"], insertcolor=p["text"], padding=4)
    st.configure("TCombobox", fieldbackground=p["input"], foreground=p["text"], background=p["surface"])
    st.map("TCombobox", fieldbackground=[("readonly", p["input"])], foreground=[("readonly", p["text"])])
    st.configure("TSpinbox", fieldbackground=p["input"], foreground=p["text"])
    st.configure("Treeview", background=p["input"], fieldbackground=p["input"], foreground=p["text"], rowheight=26)
    st.configure("Treeview.Heading", background=p["surface"], foreground=p["text"], font=(FONT, 10, "bold"))
    st.map("Treeview", background=[("selected", p["select"])], foreground=[("selected", p["text"])])
    st.configure("TLabelframe", background=p["surface"], bordercolor=p["border"])
    st.configure("TLabelframe.Label", background=p["surface"], foreground=p["text"], font=(FONT, 11, "bold"))
    root.option_add("*TCombobox*Listbox.background", p["input"])
    root.option_add("*TCombobox*Listbox.foreground", p["text"])
    return p


def style_text(t: tk.Text, p: dict):
    t.configure(background=p["input"], foreground=p["text"], insertbackground=p["text"],
                selectbackground=p["select"], selectforeground=p["text"], highlightthickness=1,
                highlightbackground=p["border"], highlightcolor=p["primary"], relief="flat", borderwidth=0)
