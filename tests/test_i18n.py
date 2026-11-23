"""Zweisprachigkeit: Katalog vollständig, Platzhalter stimmig, Spracherkennung und -wahl."""
import json
import os
import string
import sys

import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))

from i18n_extract import msgids  # noqa: E402

from sigillum import i18n  # noqa: E402

CAT = json.load(open(os.path.join(ROOT, "sigillum", "locale", "en.json"), encoding="utf-8"))


def fields(s):
    """Platzhalter eines Format-Strings: (Name, Umwandlung) – die Format-Angabe (z. B. Datum) darf je Sprache abweichen."""
    return sorted((f, c or "") for _t, f, _spec, c in string.Formatter().parse(s) if f is not None)


def test_catalog_complete_and_no_leftovers():
    ids, _dyn = msgids()
    missing = [i for i in ids if i not in CAT]
    extra = [k for k in CAT if k not in ids]
    assert not missing, missing[:5]
    assert not extra, extra[:5]


@pytest.mark.parametrize("de", sorted(CAT))
def test_placeholders_match(de):
    en = CAT[de]
    assert isinstance(en, str) and en.strip() or de.strip() == "", de
    assert fields(de) == fields(en), (de, en)
    # führende/abschließende Leerzeichen und Zeilenumbrüche bleiben gleich (Texte werden zusammengesetzt)
    assert (de[:1].isspace(), de[-1:].isspace()) == (en[:1].isspace(), en[-1:].isspace()), (de, en)
    assert de.count("\n") == en.count("\n") or "•" in de, (de, en)


def test_english_contains_no_german_umlauts():
    allowed = ("ä=ae, ö=oe, ü=ue, ß=ss",)                  # Hand-Modus: Umschrift deutscher Umlaute
    bad = [en for en in CAT.values() if any(ch in en for ch in "äöüÄÖÜß") and not any(a in en for a in allowed)]
    assert not bad, bad[:5]


def test_translate_and_fallback():
    old = i18n.LANG
    try:
        i18n.set_lang("en")
        assert i18n._("Abbrechen") == "Cancel"
        assert i18n._("unbekannter Text") == "unbekannter Text"
        assert i18n.num(1234567) == "1,234,567"
        i18n.set_lang("de")
        assert i18n._("Abbrechen") == "Abbrechen"
        assert i18n.num(1234567) == "1.234.567"
        i18n.set_lang("fr")
        assert i18n.LANG == "en"
    finally:
        i18n.set_lang(old)


def test_initial_language(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.delenv("SIGILLUM_LANG", raising=False)
    monkeypatch.setattr(i18n, "system_lang", lambda: "en")
    assert i18n.initial_lang() == "en"                     # erster Start: Systemsprache
    d = tmp_path / "SigillumArcanum"
    d.mkdir()
    (d / "einstellungen.json").write_text(json.dumps({"ui": {"lang": "de"}}), encoding="utf-8")
    assert i18n.initial_lang() == "de"                     # gespeicherte Wahl hat Vorrang
    (d / "einstellungen.json").write_text("{kaputt", encoding="utf-8")
    assert i18n.initial_lang() == "en"                     # kaputte Datei: Systemsprache
    (d / "einstellungen.json").write_text(json.dumps({"ui": {"lang": "xx"}}), encoding="utf-8")
    assert i18n.initial_lang() == "en"
    monkeypatch.setenv("SIGILLUM_LANG", "de")
    assert i18n.initial_lang() == "de"                     # Umgebungsvariable (Tests) vor allem anderen


def test_system_language_detection(monkeypatch):
    monkeypatch.setattr(i18n.sys, "platform", "linux")
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LANG", "de_AT.UTF-8")
    assert i18n.system_lang() == "de"
    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    assert i18n.system_lang() == "en"
    monkeypatch.setenv("LC_ALL", "de_CH.UTF-8")
    assert i18n.system_lang() == "de"


def test_windows_language_id(monkeypatch):
    """GetUserDefaultUILanguage: primäre Sprach-ID 0x07 = Deutsch (de-DE 0x0407, de-AT 0x0C07, de-CH 0x0807 …)."""
    import types
    for langid, want in ((0x0407, "de"), (0x0C07, "de"), (0x0807, "de"), (0x1007, "de"), (0x0409, "en"),
                         (0x040C, "en"), (0x0410, "en"), (0x0413, "en")):
        k32 = types.SimpleNamespace(GetUserDefaultUILanguage=lambda v=langid: v)
        fake = types.SimpleNamespace(windll=types.SimpleNamespace(kernel32=k32))
        monkeypatch.setattr(i18n.sys, "platform", "win32")
        monkeypatch.setitem(sys.modules, "ctypes", fake)
        assert i18n.system_lang() == want, hex(langid)


def test_detection_never_crashes(monkeypatch):
    monkeypatch.setattr(i18n.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "ctypes", None)        # Import schlägt fehl
    assert i18n.system_lang() == "en"


@pytest.mark.skipif(sys.platform != "win32", reason="echte Windows-API nur unter Windows")
def test_real_windows_detection():
    assert i18n.system_lang() in i18n.LANGS
