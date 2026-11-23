import pytest

from sigillum import core


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch, request):
    """Für Tests: Argon2id mit 64 MiB statt 1 GiB. Tests mit Marker 'realkdf' laufen mit den echten Werten."""
    if "realkdf" in request.keywords:
        return
    monkeypatch.setattr(core, "KDF_OPS", 1)
    monkeypatch.setattr(core, "KDF_MEMLOG", 26)
    monkeypatch.setattr(core, "ALLOWED_KDF", {(1, 26)})


def pytest_configure(config):
    config.addinivalue_line("markers", "realkdf: echte Argon2id-Parameter (1 GiB)")
