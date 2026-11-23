"""Sprachen / languages: Deutsch und Englisch.

Die Texte im Code sind deutsch und dienen zugleich als Schlüssel; die englische Fassung steht in
sigillum/locale/en.json ({deutsch: englisch}). Die Sprache wird beim Start EINMAL festgelegt:
  1. Umgebungsvariable SIGILLUM_LANG (de|en) – für Tests,
  2. gespeicherte Wahl in einstellungen.json ("ui" → "lang"),
  3. sonst die Windows-Anzeigesprache: Deutsch → de, alles andere → en.
Ein Wechsel in der App wird gespeichert und gilt ab dem nächsten Start.

Texts in the code are German and double as keys; English lives in sigillum/locale/en.json.
"""
import json
import locale
import os
import sys

LANGS = ("de", "en")
_HERE = os.path.dirname(os.path.abspath(__file__))
_CAT: dict = {}
LANG = "de"


def app_dir() -> str:
    return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/.config"), "SigillumArcanum")


def system_lang() -> str:
    """Deutsch nur, wenn die Anzeigesprache des Systems Deutsch ist; sonst Englisch."""
    try:
        if sys.platform == "win32":
            import ctypes
            langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            return "de" if (langid & 0x3FF) == 0x07 else "en"                 # LANG_GERMAN = 0x07
        for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
            v = os.environ.get(var, "")
            if v:
                return "de" if v.lower().startswith("de") else "en"
        loc = locale.getlocale()[0] or ""
        return "de" if loc.lower().startswith("de") else "en"
    except Exception:  # noqa: BLE001 – Spracherkennung darf den Start nie verhindern
        return "en"


def saved_lang() -> str | None:
    try:
        with open(os.path.join(app_dir(), "einstellungen.json"), encoding="utf-8") as f:
            v = json.load(f).get("ui", {}).get("lang")
        return v if v in LANGS else None
    except (OSError, ValueError, AttributeError):
        return None


def set_lang(lang: str) -> None:
    global LANG, _CAT
    LANG = lang if lang in LANGS else "en"
    if LANG == "en":
        with open(os.path.join(_HERE, "locale", "en.json"), encoding="utf-8") as f:
            _CAT = json.load(f)
    else:
        _CAT = {}


def _(text: str) -> str:
    """Übersetzt einen deutschen Text in die eingestellte Sprache (fehlt er im Katalog: unverändert)."""
    if LANG == "de":
        return text
    return _CAT.get(text, text)


def num(n: int) -> str:
    """Ganzzahl mit Tausendertrennzeichen der Sprache: 12.345 (de) / 12,345 (en)."""
    t = f"{n:,}"
    return t.replace(",", ".") if LANG == "de" else t


def initial_lang() -> str:
    env = os.environ.get("SIGILLUM_LANG")
    if env in LANGS:
        return env
    return saved_lang() or system_lang()


set_lang(initial_lang())
