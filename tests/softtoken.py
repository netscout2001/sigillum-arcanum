"""Software-Nachbildung eines YubiKeys (hmac-secret mit PIN-Pflicht) – nur für Tests."""
import hashlib
import hmac
import secrets

from sigillum import fidokey


class SoftToken(fidokey.Token):
    def __init__(self, pin="123456"):
        self.pin, self.entered = pin, pin
        self.creds = {}
        self.calls = 0
        self.tries = 8

    def _check_pin(self):
        if self.tries == 0:
            raise fidokey.FidoError("FIDO-PIN gesperrt.")
        if self.entered != self.pin:
            self.tries -= 1
            raise fidokey.FidoError("FIDO-PIN falsch.")
        self.tries = 8

    def _prf(self, cid, salt):
        return hmac.new(self.creds[cid], hashlib.sha256(b"WebAuthn PRF\0" + salt).digest(), hashlib.sha256).digest()

    def enroll(self, prf_salt):
        self.calls += 1
        self._check_pin()
        cid = secrets.token_bytes(64)
        self.creds[cid] = secrets.token_bytes(32)
        return self.derive([cid], prf_salt)

    def derive(self, cred_ids, prf_salt):
        self.calls += 1
        self._check_pin()
        for c in cred_ids:
            if c in self.creds:
                return fidokey.check_prf(c, self._prf(c, prf_salt), set(cred_ids))
        raise fidokey.FidoError("Dieser YubiKey gehört nicht zu dieser Identität.")
