"""Optionaler YubiKey (FIDO2) als vierter Faktor der Identität.

Genutzt wird ausschließlich die WebAuthn-Erweiterung PRF (CTAP "hmac-secret"): Der Key berechnet aus einem
32-Byte-Wert ein 32-Byte-Geheimnis mit einem Schlüssel, der den Chip nie verlässt. Der FIDO-Zugang wird
  * NICHT auf dem Key gespeichert (residentKey "discouraged" – belegt keinen Passkey-Platz),
  * mit credProtect "userVerificationRequired" ERZWUNGEN angelegt: ohne FIDO-PIN liefert der Key nichts,
  * bei jeder Abfrage mit userVerification "required" angesprochen; das UV-Flag der Antwort wird geprüft.

Die Bibliothek python-fido2 (Yubico) wird erst beim ersten Gebrauch geladen. Unter Windows läuft sie über die
Windows-WebAuthn-Schnittstelle (keine Administratorrechte nötig), sonst direkt über USB-HID.
"""
import secrets
import sys

from .core import SigillumError

RP_ID = "sigillum-arcanum.invalid"     # RFC 2606: ".invalid" wird nie aufgelöst – keine Webseite kann so heißen (R4-4)
ORIGIN = "https://" + RP_ID
PRF_LEN = 32
MAX_CRED_ID = 1023
TIMEOUT_MS = 120_000


class FidoError(SigillumError):
    pass


class Interaction:
    """Rückmeldungen an die Oberfläche (threadsicher von der Oberfläche umzusetzen)."""

    def status(self, text: str) -> None:
        pass

    def ask_pin(self) -> str | None:
        return None


class Token:
    """Schnittstelle: echter Key (Fido2Token) oder Nachbildung in den Tests."""

    def enroll(self, prf_salt: bytes) -> tuple[bytes, bytes]:
        """Legt einen Zugang an und liefert (Zugangs-Kennung, PRF-Geheimnis für prf_salt)."""
        raise NotImplementedError

    def derive(self, cred_ids: list, prf_salt: bytes) -> tuple[bytes, bytes]:
        """Liefert (benutzte Zugangs-Kennung, PRF-Geheimnis) für einen der angegebenen Zugänge."""
        raise NotImplementedError


def check_prf(cred_id: bytes, prf: bytes, allowed=None) -> tuple[bytes, bytes]:
    if not isinstance(prf, bytes) or len(prf) != PRF_LEN:
        raise FidoError("Der YubiKey hat kein gültiges Geheimnis geliefert (hmac-secret nicht unterstützt?).")
    if not isinstance(cred_id, bytes) or not 1 <= len(cred_id) <= MAX_CRED_ID:
        raise FidoError("Der YubiKey hat eine ungültige Zugangs-Kennung geliefert.")
    if allowed is not None and cred_id not in allowed:
        raise FidoError("Der YubiKey hat mit einem fremden Zugang geantwortet.")
    return cred_id, prf


def _prf_first(ext) -> bytes | None:
    """PRF-Ergebnis aus den Client-Erweiterungen lesen (Fido2Client: Objekte, WindowsClient: dict)."""
    prf = getattr(ext, "prf", None)
    if prf is None:
        return None
    results = prf.get("results") if isinstance(prf, dict) else getattr(prf, "results", None)
    if results is None:
        return None
    first = results.get("first") if isinstance(results, dict) else getattr(results, "first", None)
    return first if isinstance(first, bytes) else None


def _prf_enabled(ext) -> bool:
    prf = getattr(ext, "prf", None)
    if prf is None:
        return False
    enabled = prf.get("enabled") if isinstance(prf, dict) else getattr(prf, "enabled", None)
    return enabled is True


def _client_error(e) -> FidoError:
    name = getattr(getattr(e, "code", None), "name", "")
    cause = str(getattr(e, "cause", "") or "")
    if "PIN_INVALID" in cause:
        return FidoError("FIDO-PIN falsch. Achtung: Nach 8 Fehlversuchen sperrt der YubiKey.")
    if "PIN_BLOCKED" in cause or "PIN_AUTH_BLOCKED" in cause:
        return FidoError("FIDO-PIN gesperrt. Mit dem Notfall-Paket entsperren und den Key zurücksetzen.")
    if "PIN required but not provided" in cause:          # Eingabe abgebrochen (R6-2) – NICHT zurücksetzen!
        return FidoError("FIDO-PIN-Eingabe abgebrochen – nichts geändert. Bitte erneut versuchen.\n\nWICHTIG: Den "
                         "YubiKey deshalb NICHT zurücksetzen – ein Zurücksetzen löscht den Zugang für diese Identität.")
    if "PIN_NOT_SET" in cause:
        return FidoError("Am YubiKey ist keine FIDO2-PIN gesetzt. Bitte zuerst im Yubico Authenticator festlegen "
                         "(nur PIN setzen – NICHT zurücksetzen).")
    if name == "DEVICE_INELIGIBLE":
        return FidoError("Dieser YubiKey gehört nicht zu dieser Identität.")
    if name == "TIMEOUT":
        return FidoError("Zeit abgelaufen – der YubiKey wurde nicht angetippt.")
    if name == "CONFIGURATION_UNSUPPORTED":
        return FidoError("Der YubiKey unterstützt die nötige Funktion (hmac-secret mit PIN) nicht.")
    return FidoError(f"YubiKey-Fehler ({name or type(e).__name__}).")


_FLAG_BE, _FLAG_BS = 0x08, 0x10                    # WebAuthn: Backup Eligible / Backup State


def _synced(auth_data) -> bool:
    """Befund R12-N3: Ein synchronisierbarer Passkey (Handy, iCloud, Google, Passwortmanager) setzt BE/BS.
    Ein YubiKey setzt beides nie – sein Geheimnis verlässt das Gerät nicht."""
    return bool(int(getattr(auth_data, "flags", 0)) & (_FLAG_BE | _FLAG_BS))


class Fido2Token(Token):
    def __init__(self, ui: Interaction | None = None):
        self.ui = ui or Interaction()

    # ------------------------------------------------------------------ Verbindung
    def _client(self):
        try:
            from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
        except ImportError:
            raise FidoError("Die Bibliothek für den YubiKey (fido2) ist nicht installiert – installieren.bat "
                            "erneut ausführen.") from None
        collector = DefaultClientDataCollector(ORIGIN, verify=lambda rp_id, origin: rp_id == RP_ID and origin == ORIGIN)
        if sys.platform == "win32":
            from fido2.client.windows import WindowsClient
            if WindowsClient.is_available():
                return WindowsClient(collector)
        from fido2.hid import CtapHidDevice
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise FidoError("Kein YubiKey gefunden. Bitte einstecken (USB).")
        if len(devices) > 1:
            raise FidoError("Mehrere FIDO-Geräte gefunden – bitte nur den YubiKey einstecken.")
        ui = self.ui

        class _UI(UserInteraction):
            def prompt_up(self):
                ui.status("YubiKey jetzt antippen …")

            def request_pin(self, permissions, rp_id):
                return ui.ask_pin()

            def request_uv(self, permissions, rp_id):
                return True

        return Fido2Client(devices[0], collector, user_interaction=_UI())

    # ------------------------------------------------------------------ Abläufe
    def enroll(self, prf_salt: bytes) -> tuple[bytes, bytes]:
        from fido2.webauthn import (AttestationConveyancePreference, AuthenticatorAttachment,
                                    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
                                    PublicKeyCredentialHint, PublicKeyCredentialParameters,
                                    PublicKeyCredentialRpEntity, PublicKeyCredentialType,
                                    PublicKeyCredentialUserEntity, ResidentKeyRequirement,
                                    UserVerificationRequirement)
        client = self._client()
        options = PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(name="Sigillum Arcanum", id=RP_ID),
            user=PublicKeyCredentialUserEntity(name="sigillum", id=secrets.token_bytes(16),
                                               display_name="Sigillum Arcanum Identität"),
            challenge=secrets.token_bytes(32),
            pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-8),
                                 PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
            timeout=TIMEOUT_MS,
            # R4-3: nur ein externer Sicherheitsschlüssel – nicht Windows Hello, nicht ein (Cloud-)Handy-Passkey
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                resident_key=ResidentKeyRequirement.DISCOURAGED, require_resident_key=False,
                user_verification=UserVerificationRequirement.REQUIRED),
            hints=[PublicKeyCredentialHint.SECURITY_KEY],
            attestation=AttestationConveyancePreference.NONE,
            extensions={"credentialProtectionPolicy": "userVerificationRequired",
                        "enforceCredentialProtectionPolicy": True,
                        "prf": {"eval": {"first": prf_salt}}})
        self.ui.status("YubiKey: Zugang anlegen – PIN eingeben und antippen …")
        try:
            reg = client.make_credential(options)
        except Exception as e:                      # ClientError, ValueError (credProtect), OSError
            raise _client_error(e) from None
        if not _prf_enabled(reg.client_extension_results):
            raise FidoError("Der YubiKey hat hmac-secret nicht aktiviert – nicht geeignet.")
        if getattr(reg, "authenticator_attachment", None) not in (None, "cross-platform"):
            raise FidoError("Es wurde kein externer Sicherheitsschlüssel gewählt (z. B. Windows Hello oder Handy). "
                            "Bitte im Windows-Dialog „Sicherheitsschlüssel“ wählen und den YubiKey benutzen.")
        cred_id = reg.raw_id
        auth = reg.response.attestation_object.auth_data
        if not auth.is_user_verified():
            raise FidoError("Der YubiKey hat die PIN-Prüfung nicht bestätigt – abgebrochen.")
        if _synced(auth):                                 # R14-H1: fido2 liefert keine Transporte – BE/BS genügt
            raise FidoError("Gewählt wurde ein Passkey, der in eine Cloud (Handy, iCloud, Google, Passwortmanager) "
                            "gesichert werden kann – nicht geeignet. Bitte im Windows-Dialog „Sicherheitsschlüssel“ "
                            "wählen und den YubiKey benutzen.")
        self.ui.status("YubiKey: zur Kontrolle ein zweites Mal PIN eingeben und antippen …")
        return self.derive([cred_id], prf_salt)

    def derive(self, cred_ids: list, prf_salt: bytes) -> tuple[bytes, bytes]:
        from fido2.webauthn import (AuthenticatorTransport, PublicKeyCredentialDescriptor, PublicKeyCredentialHint,
                                    PublicKeyCredentialRequestOptions, PublicKeyCredentialType,
                                    UserVerificationRequirement)
        if len(prf_salt) != PRF_LEN or not cred_ids:
            raise FidoError("Interner Fehler: ungültige YubiKey-Anfrage.")
        client = self._client()
        options = PublicKeyCredentialRequestOptions(
            challenge=secrets.token_bytes(32), timeout=TIMEOUT_MS, rp_id=RP_ID,
            allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=c,
                                                             transports=[AuthenticatorTransport.USB])
                               for c in cred_ids],
            user_verification=UserVerificationRequirement.REQUIRED,
            hints=[PublicKeyCredentialHint.SECURITY_KEY],
            extensions={"prf": {"eval": {"first": prf_salt}}})
        self.ui.status("YubiKey: PIN eingeben und antippen …")
        try:
            resp = client.get_assertion(options).get_response(0)
        except Exception as e:
            raise _client_error(e) from None
        if not resp.response.authenticator_data.is_user_verified():
            raise FidoError("Der YubiKey hat die PIN-Prüfung nicht bestätigt – abgebrochen.")
        if _synced(resp.response.authenticator_data):
            raise FidoError("Der Zugang stammt nicht von einem YubiKey (synchronisierbarer Passkey) – abgelehnt. Bitte "
                            "mit dem Notfall-Paket entsperren und danach „YubiKey ersetzen“ wählen.")
        return check_prf(resp.raw_id, _prf_first(resp.client_extension_results), set(cred_ids))
