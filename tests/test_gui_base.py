"""v11: Design-Kontraste (WCAG AA) und Cloud-Erkennung – ohne Fenster."""
import os

import pytest

pytest.importorskip("tkinter")
from sigillum import gui_base as g  # noqa: E402


@pytest.mark.parametrize("name", sorted(g.PALETTES))
def test_contrast_at_least_4_5(name):
    p = g.PALETTES[name]
    for fg, bg in g.CONTRAST_PAIRS:
        assert g.contrast(p[fg], p[bg]) >= 4.5, (name, fg, bg)


def test_contrast_formula_reference_values():
    assert round(g.contrast("#000000", "#FFFFFF"), 1) == 21.0
    assert round(g.contrast("#FFFFFF", "#FFFFFF"), 1) == 1.0
    assert round(g.contrast("#767676", "#FFFFFF"), 2) == 4.54        # bekannter Grenzwert für AA


def test_is_cloud(monkeypatch, tmp_path):
    for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        monkeypatch.delenv(v, raising=False)
    assert g.is_cloud(r"C:\Users\x\OneDrive - privat\a.sakey")
    assert g.is_cloud("/home/x/Dropbox/a")
    assert not g.is_cloud(str(tmp_path / "lokal" / "a.said"))
    root = tmp_path / "Firmenablage"
    root.mkdir()
    monkeypatch.setenv("OneDriveCommercial", str(root))
    assert g.is_cloud(str(root / "x.sakey")) and not g.is_cloud(str(tmp_path / "Firmenablage2"))


def test_same_folder(tmp_path):
    a, b = tmp_path / "a.said", tmp_path / "b.sakey"
    assert g.same_folder(str(a), str(b))
    assert not g.same_folder(str(a), str(tmp_path / "sub" / "b.sakey"))


def test_config_never_stores_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(g, "APP_DIR", str(tmp_path))
    c = g.Config()
    c.set_paths("/x/id.said", "/y/kf.sakey")
    assert set(c.d) == {"device", "identity_kf", "shared_kf", "seen", "fido_ids", "backup_kf", "exported", "kf_tags",
                        "ui", "last_id", "last_ikf", "gens"}
    c.d["ui"] = {"theme": "neon", "lock_min": 1, "quick": "ja"}
    c.save()
    c2 = g.Config()
    assert c2.d["ui"] == {"theme": "light", "lock_min": g.LOCK_DEFAULT, "quick": False}
    assert os.path.exists(c2.path)


def test_generation_counter_per_identity(tmp_path, monkeypatch):
    """Befund R12-N4: höchste gesehene Generation je Identität, nur als gerätespezifischer HMAC-Schlüssel."""
    monkeypatch.setattr(g, "APP_DIR", str(tmp_path))
    c = g.Config()
    fp = b"\x01" * 32
    assert c.get_gen(fp) == 0
    c.set_gen(fp, 5)
    c.set_gen(fp, 3)                                   # nie zurück, außer ausdrücklich
    assert g.Config().get_gen(fp) == 5 and fp.hex() not in open(c.path).read()
    c.set_gen(fp, 3, only_up=False)
    assert g.Config().get_gen(fp) == 3
    c.d["gens"] = {"x": "kaputt"}
    c.save()
    assert g.Config().d["gens"] == {}
