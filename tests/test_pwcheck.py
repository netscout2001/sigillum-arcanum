"""11.4 (CodeQL alert #3): the identity passphrase check value chk.pw uses Argon2id instead of HMAC-SHA256.
Older identities (11.0–11.3) still carry the HMAC value; it is replaced as soon as the passphrase is proven."""
import json
import os

import pytest

from sigillum import core, ratchet
from sigillum.core import SigillumError
from softtoken import SoftToken

V = os.path.join(os.path.dirname(__file__), "vectors")
D = json.load(open(os.path.join(V, "identity_v11_0.json"), encoding="utf-8"))
OLD_KF = bytes.fromhex(D["kf"])
KF = core.new_keyfile()
PW = "abacus zoom kettle velvet ample cactus"
PIN = "246813"
PARTNER_PW = "zoom velvet cactus ample kettle abacus yo-yo"


def _old(name):
    with open(os.path.join(V, name), "rb") as fh:
        return fh.read()


def _old_token():
    t = SoftToken()
    t.creds = {bytes.fromhex(c): bytes.fromhex(s) for c, s in D["creds"].items()}
    return t


def _argon(chk, pw):
    ops, memlog = chk["pwk"]
    return core.passphrase_check(pw, bytes.fromhex(chk["pw_salt"]), ops, memlog).hex()


def test_new_identity_uses_argon2id():
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    chk = v.state["chk"]
    assert chk["pwk"] == [core.PWCHK_OPS, core.PWCHK_MEMLOG]
    assert chk["pw"] == _argon(chk, PW)
    assert v.same_passphrase(PW) and v.same_passphrase("  ABACUS zoom kettle velvet ample   cactus ")
    assert not v.same_passphrase(PARTNER_PW)
    w = ratchet.Vault.open(v.to_blob(), PW, PIN, KF)                       # survives saving and loading
    assert w.state["chk"]["pwk"] == chk["pwk"] and not getattr(w, "pw_upgraded", False)


def test_production_parameters():
    assert (core.PWCHK_OPS, core.PWCHK_MEMLOG) in core.PWCHK_ALLOWED


@pytest.mark.realkdf
def test_real_parameters_are_rfc9106_second_option():
    assert (core.PWCHK_OPS, core.PWCHK_MEMLOG) == (3, 26) and core.PWCHK_ALLOWED == {(3, 26)}


def test_check_value_domain_separated_and_salted():
    s1, s2 = b"\x01" * 16, b"\x02" * 16
    ops, ml = core.PWCHK_OPS, core.PWCHK_MEMLOG
    assert core.passphrase_check(PW, s1, ops, ml) != core.passphrase_check(PW, s2, ops, ml)
    assert core.passphrase_check(PW, s1, ops, ml) == core.passphrase_check(PW.upper(), s1, ops, ml)
    with pytest.raises(SigillumError):
        core.passphrase_check(PW, s1, ops + 1, ml)                         # only allowed parameters
    with pytest.raises(SigillumError):
        core.passphrase_check(PW, b"\x01" * 8, ops, ml)                    # wrong salt length
    with pytest.raises(SigillumError):
        core.passphrase_check("", s1, ops, ml)


def test_old_mode3_identity_upgraded_on_open():
    v = ratchet.Vault.open(_old("identity_v11_0_modus3.said"), D["pw"], D["pin"], OLD_KF)
    chk = v.state["chk"]
    assert v.pw_upgraded and chk["pw"] == _argon(chk, D["pw"])
    assert v.same_passphrase(D["pw"]) and not v.same_passphrase(PARTNER_PW)
    w = ratchet.Vault.open(v.to_blob(), D["pw"], D["pin"], OLD_KF)
    assert w.state["chk"] == chk and [p[1] for p in w.partners()] == ["Bén Müller"]


def test_old_mode5_daily_keeps_hmac_until_step_up():
    v = ratchet.Vault.open(_old("identity_v11_0_modus5.said"), None, D["pin"], OLD_KF, prf_fn=_old_token().derive)
    assert "pwk" not in v.state["chk"] and not getattr(v, "pw_upgraded", False)
    assert v.same_passphrase(D["pw"])                                       # old HMAC value is still checked
    with pytest.raises(SigillumError):
        v.full_keys(PW, D["pin"], OLD_KF)                                   # wrong passphrase: nothing upgraded
    assert "pwk" not in v.state["chk"]
    v.full_keys(D["pw"], D["pin"], OLD_KF)
    assert v.state["chk"]["pwk"] and v.same_passphrase(D["pw"]) and v.pw_upgraded
    w = ratchet.Vault.open(v.to_blob(), None, D["pin"], OLD_KF, prf_fn=_old_token().derive)
    assert w.state["chk"]["pw"] == v.state["chk"]["pw"]


def test_old_mode5_emergency_path_upgrades():
    code = (bytes.fromhex(D["code_id"]), bytes.fromhex(D["code"]))
    v = ratchet.Vault.open(_old("identity_v11_0_modus5.said"), D["pw"], D["pin"], OLD_KF, code=code)
    assert v.pw_upgraded and v.state["chk"]["pwk"] and v.same_passphrase(D["pw"])


@pytest.mark.parametrize("bad", ["argon2id", [3], [3, 26, 1], [4, 30], ["1", "13"], [1.0, 13.0], None])
def test_invalid_marker_rejected(bad):
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    v.state["chk"]["pwk"] = bad
    with pytest.raises(SigillumError):
        ratchet.Vault.open(v.to_blob(), PW, PIN, KF)


def test_partner_with_identity_passphrase_rejected_on_load():
    """H1 on loading also works with the Argon2id value (state crafted directly, add_partner would refuse)."""
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    pid = v.add_partner("Ben", core.new_keyfile(), PARTNER_PW, "135790")
    assert ratchet.Vault.open(v.to_blob(), PW, PIN, KF).partners()
    v.state["partners"][pid]["pw"] = core.canonical_passphrase(PW)
    with pytest.raises(SigillumError):
        ratchet.Vault.open(v.to_blob(), PW, PIN, KF)
    with pytest.raises(SigillumError, match="Identität"):
        ratchet.Vault.create("Anna", PW, PIN, KF).add_partner("Ben", core.new_keyfile(), PW, "135790")


def test_check_value_not_hmac_any_more():
    import hashlib
    import hmac
    v = ratchet.Vault.create("Anna", PW, PIN, KF)
    c = v.state["chk"]
    legacy = hmac.new(bytes.fromhex(c["pw_salt"]), core.canonical_passphrase(PW).encode(), hashlib.sha256).hexdigest()
    assert c["pw"] != legacy
