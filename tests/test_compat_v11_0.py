"""Regression: Identitätsdateien, die mit der ausgelieferten App-Version 11.0 erzeugt wurden (ohne Prüfwert chk.d),
müssen sich mit jeder späteren Version weiter öffnen lassen – Modus 3 mit Partner, Modus 5 Alltag und Notfall.
Die Dateien in tests/vectors/ sind eingefroren und enthalten nur Test-Schlüssel."""
import json
import os

from sigillum import core, ratchet
from softtoken import SoftToken

V = os.path.join(os.path.dirname(__file__), "vectors")
D = json.load(open(os.path.join(V, "identity_v11_0.json"), encoding="utf-8"))
KF = bytes.fromhex(D["kf"])


def _blob(name):
    with open(os.path.join(V, name), "rb") as fh:
        return fh.read()


def _token():
    t = SoftToken()
    t.creds = {bytes.fromhex(c): bytes.fromhex(s) for c, s in D["creds"].items()}
    return t


def test_modus3_with_partner_opens_and_gets_d_on_step_up():
    v = ratchet.Vault.open(_blob("identity_v11_0_modus3.said"), D["pw"], D["pin"], KF)
    assert v.identity.public().fp() == D["fp"] and "d" not in v.state["chk"]
    assert [p[1] for p in v.partners()] == ["Bén Müller"]
    v.full_keys(D["pw"], D["pin"], KF)
    assert "d" in v.state["chk"]
    w = ratchet.Vault.open(v.to_blob(), D["pw"], D["pin"], KF)
    assert w.state["chk"]["d"] == v.state["chk"]["d"]


def test_modus5_daily_opens_and_gets_d():
    v = ratchet.Vault.open(_blob("identity_v11_0_modus5.said"), None, D["pin"], KF, prf_fn=_token().derive)
    assert v.fido and "d" in v.state["chk"] and v.identity.public().fp() == D["fp"]
    w = ratchet.Vault.open(v.to_blob(), None, D["pin"], KF, prf_fn=_token().derive)
    assert w.state["chk"]["d"] == v.state["chk"]["d"]


def test_modus5_notfall_opens_and_can_be_reprotected():
    code = (bytes.fromhex(D["code_id"]), bytes.fromhex(D["code"]))
    v = ratchet.Vault.open(_blob("identity_v11_0_modus5.said"), D["pw"], D["pin"], KF, code=code)
    assert v.opened_with_code and "d" not in v.state["chk"]
    tok = _token()
    salt = v.new_prf_salt()
    v.protect(salt, [tok.derive(v.fido_cred_ids(), salt)], v.new_code(), v.full_keys(D["pw"], D["pin"], KF))
    assert ratchet.Vault.open(v.to_blob(), None, D["pin"], KF, prf_fn=tok.derive).fido


def test_fixture_really_from_11_0():
    assert D["kdf"] == [core.KDF_OPS, core.KDF_MEMLOG]
