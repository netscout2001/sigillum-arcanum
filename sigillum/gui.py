"""Sigillum Arcanum – grafische Oberfläche (Tkinter, offline). Version 11.4.

Aufbau: Kopfzeile (Sperrstatus, Restzeit, Sperren), Navigation links, Seiten rechts, Statuszeile unten.
Seiten und Assistenten: gui_pages.py, gui_wizard.py. Gemeinsame Bausteine: gui_base.py.
"""
import hashlib
import hmac
import os
import queue
import re
import secrets
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import codec, core, fidokey, handmode, notfall, pdfout, ratchet, shamir          # noqa: F401 (Tests patchen)
from .gui_base import (ERRORS, FONT_FAMILY, MONO, QUICK_TRIES, Config, apply_theme, clipboard_history_enabled,  # noqa: F401
                       gap_text, get_text, is_cloud, load_private_font, read_file, read_keyfile_path, same_drive,
                       same_folder, scrolled_text, set_text, style_text, wipe, workstation_locked, write_atomic)
from .gui_pages import PagesMixin
from .gui_wizard import FactorsDialog
from .i18n import _

NAV = (("start", _("Start")), ("write", _("Schreiben")), ("read", _("Lesen")), ("contacts", _("Kontakte & Partner")),
       ("keys", _("Schlüssel & Sicherheit")), ("hand", _("Hand-Modus")), ("backup", _("Backup")))


class App(PagesMixin, tk.Tk):
    def __init__(self):
        load_private_font()
        super().__init__()
        self.title("Sigillum Arcanum")
        self.geometry("1220x880")
        self.minsize(1000, 720)
        self.cfg = Config()
        self.glyph_font = (FONT_FAMILY, 26)
        self.busy = False
        self.vault = None
        self.vault_path = None
        self.vault_hash = None
        self.vault_gen = 0                    # erhöht bei jedem Ent-/Sperren: veraltete Ergebnisse werden verworfen
        self._cloud_warned = set()
        self._ui_q = queue.Queue()            # Anfragen des YubiKey-Hintergrund-Threads an die Oberfläche
        self._recovery_kf = None              # Schlüsseldatei aus dem Notfall-Paket, nur bis zur Erneuerung
        self._recovery_secret = None          # (Passphrase, PIN) nach Notfall-Entsperren, nur bis zur Erneuerung
        self._quick = None                    # (salt, key) – Schnell-Entsperren, nur solange entsperrt
        self._sealed = None                   # versiegelte Sitzung nach automatischer Sperre (Schnell-Entsperren)
        self._gen_key = secrets.token_bytes(32)  # R12-M1: Kennungen der in dieser Sitzung gewürfelten Passphrasen
        self._generated = set()
        self._pt_tags = set()
        self._weak_pin = None
        self._last_act = time.monotonic()
        self._lock_check = 0
        self._texts = []
        self.pal = apply_theme(self, self.cfg.ui("theme"))

        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        for seq in ("<KeyPress>", "<ButtonPress>", "<MouseWheel>"):
            self.bind_all(seq, self._activity, add="+")
        self.refresh_all()
        self.show("start")
        self.after(100, self._ui_tick)
        self.after(1000, self._idle_tick)
        if clipboard_history_enabled():
            self.after(400, lambda: messagebox.showwarning(
                _("Zwischenablage-Verlauf aktiv"),
                _("Der Windows-Zwischenablage-Verlauf (Win+V) ist eingeschaltet.\n\nAlles, was du kopierst, "
                  "bleibt dort gespeichert. Kopiere niemals Klartext oder Schlüssel. Abschalten: Einstellungen > "
                  "System > Zwischenablage.")))
        if not os.environ.get("SIGILLUM_NO_WIZARD") and not self.cfg.d.get("last_id"):
            self.after(700, self._offer_wizard)

    # ================================================= Aufbau
    def _build_layout(self):
        head = ttk.Frame(self, style="Head.TFrame", padding=(14, 8))
        head.pack(fill="x")
        ttk.Label(head, text=_("Sigillum Arcanum"), style="AppTitle.TLabel").pack(side="left")
        self.l_vault = ttk.Label(head, text=_("gesperrt"), style="Locked.TLabel")
        self.l_vault.pack(side="left", padx=16)
        self.l_lockin = ttk.Label(head, text="", style="HeaderMuted.TLabel")
        self.l_lockin.pack(side="left")
        self.b_theme = ttk.Button(head, text="", command=self.toggle_theme)
        self.b_theme.pack(side="right")
        # Ein Knopf, der mit dem Zustand wechselt: entsperrt "Jetzt sperren", gesperrt "Entsperren"
        self.b_lock = ttk.Button(head, text=_("Entsperren"), style="Primary.TButton", command=self._head_lock_button)
        self.b_lock.pack(side="right", padx=8)
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        side = ttk.Frame(body, style="Side.TFrame", width=230)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        ttk.Label(side, text=_("Menü"), style="SideTitle.TLabel").pack(fill="x")
        self.nav = {}
        for key, label in NAV:
            b = ttk.Button(side, text=label, style="Nav.TButton", command=lambda k=key: self.show(k))
            b.pack(fill="x")
            self.nav[key] = b
        self.content = ttk.Frame(body, padding=(18, 14))
        self.content.pack(side="left", fill="both", expand=True)
        self.pages = {}
        for key, _u in NAV:
            f = ttk.Frame(self.content)
            self.pages[key] = f
            getattr(self, f"page_{key}")(f)
        self.status = ttk.Label(self, text=_("Bereit. Die App arbeitet vollständig offline."), style="Status.TLabel",
                                anchor="w")
        self.status.pack(fill="x")
        self._update_theme_button()

    def show(self, key):
        for k, f in self.pages.items():
            f.pack_forget()
            self.nav[k].configure(style="NavActive.TButton" if k == key else "Nav.TButton")
        self.pages[key].pack(fill="both", expand=True)
        self.current = key
        if key == "start":
            self.refresh_start()

    def register_text(self, t):
        self._texts.append(t)
        style_text(t, self.pal)

    def toggle_theme(self):
        name = "dark" if self.cfg.ui("theme") == "light" else "light"
        self.cfg.set_ui("theme", name)
        self.pal = apply_theme(self, name)
        for t in self._texts:
            style_text(t, self.pal)
        for c in self._canvases:
            c.configure(background=self.pal["bg"])
        self._update_theme_button()

    def _update_theme_button(self):
        self.b_theme.configure(text=_("Dunkles Design") if self.cfg.ui("theme") == "light" else _("Helles Design"))

    def set_status(self, s):
        self.status.configure(text=s)

    def refresh_all(self):
        self.refresh_contacts()
        self.refresh_partners()
        self.refresh_fido()
        self.refresh_start()
        self._refresh_badge()

    def _refresh_badge(self):
        v = self.vault
        if v:
            self.l_vault.configure(text=(_("entsperrt: {0} (YubiKey)") if v.fido else _("entsperrt: {0}")).format(v.identity.name),
                                   style="Open.TLabel")
        else:
            self.l_vault.configure(text=_("gesperrt"), style="Locked.TLabel")
            self.l_lockin.configure(text="")
        if v:
            self.b_lock.configure(text=_("Jetzt sperren"), style="Danger.TButton")
        else:
            self.b_lock.configure(text=_("Mit PIN fortsetzen") if self._sealed else _("Entsperren"), style="Primary.TButton")

    def _head_lock_button(self):
        """Gesperrt: zur Seite „Start“ und ins richtige Feld; entsperrt: sofort sperren."""
        if self.vault:
            return self.lock(_("Identität gesperrt."))
        self.show("start")
        self.after_idle(self.focus_unlock)

    def _offer_wizard(self):
        if self.vault is None and messagebox.askyesno(
                _("Willkommen bei Sigillum Arcanum"),
                _("Es ist noch keine Identität eingerichtet.\n\nDer Einrichtungs-Assistent führt dich Schritt für "
                  "Schritt durch alles Nötige (ca. 15 Minuten; du brauchst einen USB-Stick, einen lokalen Drucker "
                  "und Papier).\n\nJetzt starten?")):
            self.start_wizard()

    # ================================================= Aktivität und automatische Sperre (v11, Baustein 1 B)
    def _activity(self, _e=None):
        self._last_act = time.monotonic()

    def _idle_tick(self):
        try:
            if self.vault is not None and not self.busy:
                limit = int(self.cfg.ui("lock_min")) * 60
                left = limit - (time.monotonic() - self._last_act)
                self._lock_check += 1
                if left <= 0:
                    self.auto_lock(_("Automatisch gesperrt: keine Bedienung seit {0} Minuten.").format(self.cfg.ui('lock_min')))
                elif self._lock_check % 5 == 0 and workstation_locked():
                    self.auto_lock(_("Automatisch gesperrt: Windows-Bildschirm wurde gesperrt."))
                else:
                    m, s = divmod(int(left), 60)
                    self.l_lockin.configure(text=_("Sperre in {0}:{1:02d}").format(m, s))
        finally:
            self.after(1000, self._idle_tick)

    def clear_clipboard_if_plaintext(self):
        """Befund R12-H2: Steht Klartext aus einem Klartextfeld in der Zwischenablage (z. B. per Strg+C kopiert),
        wird sie beim Sperren und Schließen geleert. Geheimtext bleibt (er ist zum Weitergeben da)."""
        try:
            clip = self.clipboard_get()
        except tk.TclError:
            return
        c = clip.strip()
        if not c:
            return
        tags = {self._gen_tag(c)} | {self._gen_tag(x.strip()) for x in c.splitlines() if x.strip()}
        if tags & self._pt_tags:                       # R14-H2: Klartext dieser Sitzung, auch wenn das Feld leer ist
            self.clipboard_clear()
            return
        for w in (self.t_plain, self.t_out, self.t_hplain, self.t_pad, self.t_shares):
            body = get_text(w)
            if body.strip() and c in body:
                self.clipboard_clear()
                return

    def note_plaintext(self, text):
        """Nur Kennungen (HMAC mit Sitzungsschlüssel) des Klartexts und seiner Zeilen merken – nie den Text."""
        for x in [text] + text.splitlines():
            if x.strip():
                self._pt_tags.add(self._gen_tag(x.strip()))

    def clear_sensitive(self):
        """Klartext- und Geheimnisfelder leeren (beim Sperren und Schließen)."""
        self.clear_clipboard_if_plaintext()
        for v in (self.v_pass, self.v_pin, self.v_ipass, self.v_ipin, self.v_dice, self.v_qpin):
            v.set("")
        for w in (self.t_plain, self.t_out, self.t_hplain, self.t_pad, self.t_shares):
            set_text(w, "")

    def auto_lock(self, reason):
        """Sperre nach Zeit: mit eingeschaltetem Schnell-Entsperren wird die Sitzung mit der PIN versiegelt."""
        sealed = None
        v = self.vault
        if (self._quick and self.cfg.ui("quick") and v and not self._recovery_secret
                and not v.opened_with_code and not v.recovery_pending):        # Befund R11-M2
            salt, key = self._quick
            sealed = {"salt": salt, "blob": core.seal(key, self.vault.session_bytes(), b"SIGILLUM-v11-quick"),
                      "path": self.vault_path, "hash": self.vault_hash, "tries": 0, "name": self.vault.identity.name}
        self.lock(reason, force=True)
        self._sealed = sealed
        self.clear_sensitive()
        self.show("start")

    # ================================================= Faktoren lesen (Befund H1: getrennt)
    def _toggle_show(self):
        for e in self._secret_entries:
            e.configure(show="" if self.v_show.get() else "•")

    def _pick(self, var, title, pattern):
        p = filedialog.askopenfilename(title=title, filetypes=[(title, pattern), (_("Alle Dateien"), "*.*")])
        if p:
            var.set(p)

    def clear_shared(self):
        for v in (self.v_pass, self.v_pin, self.v_kf):
            v.set("")
        self.set_status(_("Felder des gemeinsamen Schlüssels geleert."))

    def shared_factors(self):
        """Gemeinsame Faktoren (von Hand) lesen und gegen die Identität abgrenzen (Befund H1)."""
        pw, pin = self.v_pass.get(), self.v_pin.get()
        if not pw or not pin:
            raise core.SigillumError(_("Bitte Passphrase und PIN des gemeinsamen Schlüssels angeben."))
        kf = read_keyfile_path(self.v_kf.get(), _("den gemeinsamen Schlüssel"))
        d = core.keyfile_digest(kf)
        if self.cfg.has("identity_kf", d) or (self.vault and d == self.vault.kf_digest):
            raise core.SigillumError(_("Diese Schlüsseldatei schützt eine Identität. Für gemeinsame Nachrichten "
                                       "eine EIGENE Schlüsseldatei verwenden – sonst könnte dein Gesprächspartner "
                                       "deine Identität öffnen."))
        if self.vault and self.vault.same_passphrase(pw):
            raise core.SigillumError(_("Diese Passphrase schützt deine Identität. Für gemeinsame Nachrichten eine "
                                       "andere Passphrase verwenden."))
        self.warn_cloud(self.v_kf.get(), _("Die Schlüsseldatei des gemeinsamen Schlüssels"))
        return pw, pin, kf, d

    def dice_passphrase(self):
        pw = core.generate_passphrase(7)
        self._generated.add(self._gen_tag(pw))
        self.v_dice.set(pw)

    def _gen_tag(self, pw):
        return hmac.new(self._gen_key, core.canonical_passphrase(pw).encode("utf-8"), hashlib.sha256).digest()

    def was_generated(self, pw) -> bool:
        return self._gen_tag(pw) in self._generated

    def confirm_foreign_pw(self, pw) -> bool:
        """R14-N2: Eine von außen eingetippte Passphrase kann die App nicht als zufällig erkennen. Einmal je Passphrase
        und Sitzung nachfragen (ob sie vom Übergabeblatt bzw. aus einer App stammt)."""
        t = self._gen_tag(pw)
        if t in self._generated:
            return True
        if not messagebox.askyesno(
                _("Passphrase prüfen"), _("Diese Passphrase wurde nicht hier gewürfelt.\n\nStammt sie vom "
                                        "Übergabeblatt deines Partners oder aus seiner Sigillum-App, ist sie in "
                                        "Ordnung. Selbst ausgedachte Wortketten – auch aus Listenwörtern – kann "
                                        "eine KI erraten; dann bitte mit „Erzeugen“ eine neue würfeln.\n\nStammt "
                                        "sie aus einer App bzw. vom Übergabeblatt?"), icon="warning"):
            return False
        self._generated.add(t)
        return True

    def identity_factors(self, strict=True, need_pw=True):
        """strict=True beim Erzeugen (Überschneidung = abgelehnt), False beim Entsperren (nur Warnung,
        damit niemand aus seiner eigenen Identität ausgesperrt wird). need_pw=False: Alltag mit YubiKey."""
        pw, pin = self.v_ipass.get(), self.v_ipin.get()
        if (need_pw and not pw) or not pin:
            raise core.SigillumError(_("Bitte Passphrase und PIN der Identität angeben.") if need_pw
                                     else _("Bitte die PIN der Identität angeben."))
        kf = read_keyfile_path(self.v_ikf.get(), _("die Identität"))
        d = core.keyfile_digest(kf)
        shared_kf = None
        try:
            if self.v_kf.get():
                shared_kf = core.keyfile_digest(read_keyfile_path(self.v_kf.get(), _("den gemeinsamen Schlüssel")))
        except core.SigillumError:
            pass
        problems = []
        if self.cfg.has("shared_kf", d) or d == shared_kf:
            problems.append(_("Diese Schlüsseldatei wird auch für gemeinsame Nachrichten verwendet."))
        if pw and self.v_pass.get() and core.canonical_passphrase(self.v_pass.get()) == core.canonical_passphrase(pw):
            problems.append(_("Identität und gemeinsamer Schlüssel haben dieselbe Passphrase."))
        if problems and strict:
            raise core.SigillumError(" ".join(problems) + _(" Die Identität braucht EIGENE Faktoren "
                                                            "(Einrichtungs-Assistent oder neue Schlüsseldatei und "
                                                            "Passphrase erzeugen)."))
        if problems:
            messagebox.showwarning(_("Identität gefährdet"), " ".join(problems) + _("\n\nWer die gemeinsamen "
                                                                                   "Faktoren kennt, kann diese "
                                                                                   "Identität öffnen, als du "
                                                                                   "signieren und deine "
                                                                                   "Nachrichten lesen. Erzeuge "
                                                                                   "eine neue Identität mit "
                                                                                   "eigenen Faktoren und tausche "
                                                                                   "sie mit deinen Kontakten."))
        return pw, pin, kf, d

    def ask_factors(self, title, text):
        """Passphrase + PIN der Identität für eine sicherheitskritische Änderung (Schritt-Bestätigung)."""
        dlg = FactorsDialog(self, title, text)
        self.wait_window(dlg)
        return dlg.result

    # ================================================= Identität entsperren / speichern
    def _file_mode_of(self, path):
        try:
            with open(path, "rb") as fh:
                return ratchet.file_mode(fh.read(16))               # nur den Kopf lesen
        except (OSError, core.SigillumError):
            return None

    def unlock(self):
        path = self.v_id.get()
        quick_on = bool(self.cfg.ui("quick"))

        def prepare():
            if not path:
                raise core.SigillumError(_("Bitte die Identitätsdatei wählen."))
            blob = read_file(path)
            mode = ratchet.file_mode(blob)
            daily = mode == core.MODE_IDENTITY_FIDO
            pw, pin, kf, d = self.identity_factors(strict=False, need_pw=not daily)
            self.warn_cloud(path, _("Deine Identitätsdatei"))
            self.warn_cloud(self.v_ikf.get(), _("Die Schlüsseldatei deiner Identität"))
            if same_folder(path, self.v_ikf.get()):
                messagebox.showwarning(
                    _("Faktoren am selben Ort"), _("Identitätsdatei und ihre Schlüsseldatei liegen im SELBEN Ordner. "
                                                "Wer den Ordner kopiert, hat beide. Lege die Schlüsseldatei auf "
                                                "einen USB-Stick."))
            token = fidokey.Fido2Token(self.fido_ui()) if daily else None

            def work():
                if daily:
                    v = ratchet.Vault.open(blob, None, pin, kf, prf_fn=token.derive)
                else:
                    v = ratchet.Vault.open(blob, pw, pin, kf)
                quick = None
                if quick_on:
                    salt = secrets.token_bytes(core.SALT_LEN)
                    quick = (salt, core.derive_quick_key(pin, salt))
                try:
                    weak = core.pin_problem(pin)              # nur ein Hinweis – darf das Entsperren nie verhindern
                except Exception:                             # noqa: BLE001 (R14-M2)
                    weak = None
                return v, hashlib.sha256(blob).digest(), d, quick, weak
            return work

        def done(res):
            v, h, d, quick, weak = res
            if not self._rollback_ok(v):
                self.v_ipass.set("")
                self.v_ipin.set("")
                return self.set_status(_("Nicht geöffnet: ältere Fassung der Identitätsdatei."))
            self._adopt(v, h, path)
            self._quick = quick
            self._weak_pin = weak                          # Befund R12-N2: nur der Hinweis, nie die PIN
            self.cfg.note("identity_kf", d)
            self.cfg.set_paths(path, self.v_ikf.get())
            self.v_ipass.set("")
            self.v_ipin.set("")
            self.after_unlock()
            if self.vault.fido and self.vault.recovery_pending:          # Befund R4-2
                messagebox.showwarning(_("Notfall-Code nicht erneuert"), _("Mit dieser Identität wurde zuletzt das "
                                                                        "Notfall-Paket benutzt, aber kein neues "
                                                                        "erzeugt. Das ist jetzt Pflicht."))
                self._after_recovery()
        self.run(_("Entsperre Identität"), prepare, done)

    def _rollback_ok(self, v) -> bool:
        """Befund R12-N4: Ist die geöffnete Datei älter als die zuletzt auf diesem Rechner gesehene Fassung?"""
        fp = v.identity.public().fp_raw()
        seen = self.cfg.get_gen(fp)
        if v.gen >= seen:
            return True
        if messagebox.askyesno(
                _("Ältere Fassung der Identitätsdatei"), _("Diese Identitätsdatei ist ÄLTER als die Fassung, die "
                                                          "zuletzt auf diesem Rechner benutzt wurde (Stand {0} "
                                                          "statt {1}).\n\nDas passiert, wenn ein Backup oder eine "
                                                          "alte Kopie zurückgespielt wurde – oder wenn jemand die "
                                                          "Datei ausgetauscht hat. Folgen: bereits gelöschte "
                                                          "Schlüssel sind wieder da, schon gelesene Nachrichten "
                                                          "werden nicht als Wiederholung erkannt, und schon "
                                                          "benutzte Zufallsblätter des Hand-Modus gelten wieder "
                                                          "als frei.\n\nNur fortfahren, wenn du das Backup "
                                                          "bewusst eingespielt hast. Danach beim Kontakt "
                                                          "„Schlüsselwechsel neu starten“ und keine alten "
                                                          "Zufallsblätter mehr benutzen.\n\nTrotzdem öffnen?").format(v.gen, seen), icon="warning"):
            self.cfg.set_gen(fp, v.gen, only_up=False)
            return True
        return False

    def _note_gen(self):
        if self.vault is not None:
            self.cfg.set_gen(self.vault.identity.public().fp_raw(), self.vault.gen)

    def _adopt(self, v, h, path):
        self.vault, self.vault_hash, self.vault_path = v, h, path
        self.vault_gen += 1
        self._sealed = None
        self._last_act = time.monotonic()
        self._note_gen()

    def quick_unlock(self):
        """v11: nach automatischer Sperre mit der App-PIN fortsetzen (nur solange die App läuft; 3 Versuche)."""
        s = self._sealed
        pin = self.v_qpin.get()
        if not s or self.busy:                     # Befund R11-M5: Klick während der Prüfung zählt nicht
            return
        if not pin:
            return messagebox.showerror("Sigillum Arcanum", _("Bitte die PIN eingeben."))

        def prepare():
            def work():
                # Befund R11-H-a: erst die Datei prüfen, dann entsiegeln – sonst verrät „Datei geändert“ die PIN
                if hashlib.sha256(read_file(s["path"])).digest() != s["hash"]:
                    raise core.SigillumError("EXTERN-QUICK")
                data = core.unseal(core.derive_quick_key(pin, s["salt"]), s["blob"], b"SIGILLUM-v11-quick")
                return ratchet.Vault.from_session(data)
            return work

        def done(v):
            salt = secrets.token_bytes(core.SALT_LEN)
            self.v_qpin.set("")
            if v.opened_with_code or v.recovery_pending:            # Befund R11-M2 (zweite Sicherung)
                self._sealed = None
                self.refresh_start()
                return messagebox.showwarning("Sigillum Arcanum", _("Nach Benutzung des Notfall-Pakets ist "
                                                                    "Schnell-Entsperren nicht möglich. Bitte "
                                                                    "normal entsperren."))
            self._adopt(v, s["hash"], s["path"])
            self._quick = None
            self.after_unlock()
            # Schnell-Entsperren erneut vorbereiten (neues Salz) – im Hintergrund, ohne die Bedienung aufzuhalten
            self.run(_("Bereite Schnell-Entsperren vor"), lambda: (lambda: core.derive_quick_key(pin, salt)),
                     lambda k: setattr(self, "_quick", (salt, k)) if self.vault is v else None)

        def fail():
            self.v_qpin.set("")
            if not self._sealed:
                return
            self._sealed["tries"] += 1
            if self._sealed["tries"] >= QUICK_TRIES:
                self._sealed = None
                messagebox.showwarning(_("Schnell-Entsperren gesperrt"),
                                       _("{0} falsche PINs – die versiegelte Sitzung wurde verworfen. Bitte "
                                         "normal entsperren.").format(QUICK_TRIES))
            self.refresh_start()
        self.run(_("Entsperre mit PIN"), prepare, done, fail)

    def after_unlock(self):
        v = self.vault
        fp = v.identity.public().fp_raw()
        self.refresh_all()
        if getattr(v, "pw_upgraded", False):          # 11.4: neuer Passphrase-Prüfwert (Argon2id) gleich speichern
            self.after_idle(lambda: self.vault is v and not self.busy and self.vault_op(
                _("Speichere Prüfwert"), lambda c: None, lambda _u: None))
        self.set_status(_("Identität entsperrt. Passphrase und PIN wurden aus den Feldern gelöscht."))
        if v.fido:
            self.cfg.set_fido(fp, True)
        elif self.cfg.had_fido(fp):
            messagebox.showwarning(
                _("Kopie ohne YubiKey"), _("Diese Identität war auf diesem Rechner mit einem YubiKey geschützt – die "
                                        "gerade geöffnete Datei aber NICHT. Vermutlich ist es eine ältere "
                                        "Kopie.\n\nÄltere Kopien lassen sich ohne YubiKey öffnen. Lösche sie und "
                                        "arbeite mit der aktuellen Datei. Hast du den YubiKey bewusst "
                                        "ausgeschaltet, kannst du diese Meldung ignorieren."))

    def lock(self, reason=None, force=False, keep=None):
        if self.busy and not force:
            return messagebox.showinfo("Sigillum Arcanum", _("Bitte warten, bis der laufende Vorgang fertig ist."))
        self.vault_gen += 1
        self.vault = self.vault_path = self.vault_hash = None
        self._recovery_kf = self._recovery_secret = None
        self._quick = None
        self._sealed = None
        self.close_dialogs(keep)                               # Befund R11-M3
        self.clear_sensitive()                                 # Befund R11-M4
        self.refresh_all()
        self.set_status(reason or _("Identität gesperrt."))

    def close_dialogs(self, keep=None):
        """Beim Sperren alle offenen Assistenten und Dialoge schließen; sie können Passphrasen und PINs zeigen.
        keep = das Fenster, das gerade selbst sperrt (Einrichtungs-Assistent nach dem Erzeugen)."""
        for w in list(self.winfo_children()):
            if isinstance(w, tk.Toplevel) and w is not keep:
                try:
                    if hasattr(w, "cleanup"):
                        w.cleanup()
                except tk.TclError:
                    pass
                try:
                    w.destroy()
                except tk.TclError:
                    pass

    def require_vault(self):
        if not self.vault:
            raise core.SigillumError(_("Bitte zuerst deine Identität entsperren (Seite „Start“)."))

    def save_work(self, clone):
        """Läuft im Hintergrund: prüft, dass die Datei nicht von außen verändert wurde, und schreibt sie."""
        path, expected = self.vault_path, self.vault_hash

        def work():
            if hashlib.sha256(read_file(path)).digest() != expected:
                raise core.SigillumError("EXTERN")
            blob = clone.to_blob()
            write_atomic(path, blob)
            return hashlib.sha256(blob).digest()
        return work

    def vault_op(self, label, action, done, fail=None):
        """Änderung an einer Arbeitskopie; übernommen wird sie erst, wenn sie gespeichert ist."""
        gen = self.vault_gen

        def prepare():
            self.require_vault()
            clone = self.vault.clone()
            save = self.save_work(clone)

            def work():
                res = action(clone)
                return res, clone, save()
            return work

        def finished(r):
            res, clone, h = r
            if gen != self.vault_gen:
                return messagebox.showwarning("Sigillum Arcanum", _("Die Identität wurde zwischenzeitlich gesperrt."))
            self.vault, self.vault_hash = clone, h
            self._note_gen()
            done(res)
        self.run(label, prepare, finished, fail)

    def confirm_local(self, folder) -> bool:
        """R6-1: Druck-/Backup-Ordner in einer Cloud? Dann ausdrücklich nachfragen."""
        if not is_cloud(folder):
            return True
        return messagebox.askyesno(
            _("Cloud-Ordner"), _("Der Ordner\n{0}\nliegt anscheinend in einem synchronisierten Cloud-Ordner "
                              "(OneDrive, Dropbox …). Geheime Dateien würden dann hochgeladen und blieben im "
                              "Versionsverlauf, auch wenn die App sie löscht.\n\nTrotzdem diesen Ordner verwenden?").format(folder), icon="warning")

    def warn_cloud(self, path, what):
        """v11: auch Schlüsseldateien werden geprüft (vorher nur die Identitätsdatei). Einmal je Pfad."""
        if not path or path in self._cloud_warned or not is_cloud(path):
            return
        self._cloud_warned.add(path)
        messagebox.showwarning(
            _("Datei in einem Cloud-Ordner"),
            _("{0} liegt in einem synchronisierten Ordner (z. B. OneDrive):\n{1}\n\nDer Cloud-Anbieter – und wer "
              "dein Konto übernimmt – hat damit eine Kopie; alte Versionen bleiben im Versionsverlauf. "
              "Schlüsseldateien gehören auf einen USB-Stick, die Identitätsdatei in einen lokalen Ordner. Danach "
              "in der Cloud die Dateien, ihre Versionen und den Papierkorb löschen.").format(what, path))

    # ================================================= YubiKey (optional, nur Identität)
    def fido_ui(self):
        app = self

        class TkInteraction(fidokey.Interaction):
            """Läuft im Hintergrund-Thread: Anfragen gehen über eine Warteschlange an die Oberfläche."""

            def status(self, text):
                app._ui_q.put(("status", text, None, None))

            def ask_pin(self):
                ev, box = threading.Event(), {}
                app._ui_q.put(("pin", None, box, ev))
                ev.wait(300)
                return box.get("pin")
        return TkInteraction()

    def _ui_tick(self):
        try:
            while True:
                kind, text, box, ev = self._ui_q.get_nowait()
                if kind == "status":
                    self.set_status(text)
                elif kind == "pin":
                    box["pin"] = simpledialog.askstring("YubiKey", _("FIDO2-PIN des YubiKeys:"), show="•", parent=self)
                    ev.set()
        except queue.Empty:
            pass
        self.after(100, self._ui_tick)

    def refresh_fido(self):
        if not hasattr(self, "l_fido"):
            return
        v = self.vault
        if not v:
            text = _("Identität gesperrt.")
        elif v.fido:
            text = (_("EIN – {0} YubiKey(s) und ein Notfall-Paket schützen diese Identität. Im Alltag genügen "
                      "PIN, Schlüsseldatei und YubiKey; die Passphrase brauchst du nur im Notfall und für "
                      "Änderungen hier.").format(len(v.fido_cred_ids())))
        else:
            text = _("AUS – die Identität ist mit Passphrase, PIN und Schlüsseldatei geschützt.")
        self.l_fido.configure(text=text)

    def _identity_keyfile(self, kf=None):
        """Schlüsseldatei der Identität – muss nachweislich zu dieser Identität gehören."""
        kf = kf or self._recovery_kf or read_keyfile_path(self.v_ikf.get(), _("die Identität"))
        if core.keyfile_digest(kf) != self.vault.kf_digest:
            raise core.SigillumError(_("Die eingetragene Schlüsseldatei gehört nicht zu dieser Identität. Bitte "
                                       "auf der Seite „Start“ die richtige Identitäts-Schlüsseldatei wählen."))
        return kf

    def _secret_for_change(self, what):
        """(Passphrase, PIN) für sicherheitskritische Änderungen: nach Notfall aus dem Notfall-Entsperren, sonst
        abgefragt. None = abgebrochen."""
        if self._recovery_secret:
            return self._recovery_secret
        return self.ask_factors(what, _("Zur Bestätigung braucht die App die Passphrase und die PIN deiner "
                                        "Identität (Schritt-Bestätigung für sicherheitskritische Änderungen)."))

    def fido_enable(self, secret=None, kf=None, on_done=None):
        try:
            self.require_vault()
        except core.SigillumError as e:
            return messagebox.showerror("Sigillum Arcanum", str(e))
        if self.vault.fido:
            return messagebox.showinfo("YubiKey", _("Der YubiKey ist bereits eingeschaltet."))
        if not messagebox.askokcancel(
                _("YubiKey einschalten"),
                _("Der YubiKey wird ein zusätzlicher Faktor deiner Identität. Danach öffnet sie sich im Alltag "
                  "mit PIN + Schlüsseldatei + YubiKey (FIDO-PIN + Antippen) – die Passphrase brauchst du dann nur "
                  "noch im Notfall (mit dem Notfall-Paket) und für Änderungen am "
                  "YubiKey-Schutz.\n\nVoraussetzungen:\n• Am YubiKey ist eine FIDO2-PIN gesetzt (Yubico "
                  "Authenticator), am besten 6 zufällige Ziffern.\n• Ein Ordner für das Notfall-Paket (am besten "
                  "USB-Stick) und ein lokaler Drucker.\n\nHinweis: YubiKeys mit Firmware vor 5.7 sind von der "
                  "Yubico-Meldung YSA-2024-03 betroffen (Klonen mit Laborausrüstung, Key UND FIDO-PIN nötig). Die "
                  "übrigen Faktoren schützen weiter.\n\nFortfahren?")):
            return
        self._fido_setup("new", forced=False, secret=secret, kf=kf, on_done=on_done)

    def fido_renew(self):
        try:
            self.require_vault()
        except core.SigillumError as e:
            return messagebox.showerror("Sigillum Arcanum", str(e))
        if not self.vault.fido:
            return messagebox.showinfo("YubiKey", _("Der YubiKey ist ausgeschaltet – es gibt kein Notfall-Paket."))
        self._fido_setup("keep", forced=False)

    def fido_replace(self):
        try:
            self.require_vault()
        except core.SigillumError as e:
            return messagebox.showerror("Sigillum Arcanum", str(e))
        if not self.vault.fido:
            return messagebox.showinfo("YubiKey", _("Der YubiKey ist ausgeschaltet – „YubiKey einschalten“ benutzen."))
        if messagebox.askokcancel(_("YubiKey ersetzen"), _("Den NEUEN YubiKey einstecken. Der bisherige Key öffnet "
                                                        "die Identität danach nicht mehr; es entsteht auch ein "
                                                        "neues Notfall-Paket.\n\nFortfahren?")):
            self._fido_setup("new", forced=False)

    def _relock(self):
        self.lock(_("Identität gesperrt: Notfall-Code wurde nicht erneuert."), force=True)

    def fido_disable(self, forced=False):
        try:
            self.require_vault()
        except core.SigillumError as e:
            if forced:
                self._relock()
            return messagebox.showerror("Sigillum Arcanum", str(e))
        if not self.vault.fido:
            return messagebox.showinfo("YubiKey", _("Der YubiKey ist bereits ausgeschaltet."))
        if not messagebox.askyesno(
                _("YubiKey ausschalten"), _("Danach öffnet sich die Identität wieder NUR mit Passphrase + PIN + "
                                         "Schlüsseldatei – ohne YubiKey, und die Passphrase wird wieder bei jedem "
                                         "Entsperren gebraucht.\n\nDie Notfall-Papiere enthalten dann weiterhin "
                                         "eine gültige Schlüsseldatei: Bewahre sie wie ein Schlüsseldatei-Backup "
                                         "auf oder vernichte sie.\n\nWirklich ausschalten?"), icon="warning"):
            if forced:
                self._relock()
            return
        try:
            kf = self._identity_keyfile()
        except core.SigillumError as e:
            if forced:
                self._relock()
            return messagebox.showerror("YubiKey", str(e))
        secret = self._secret_for_change(_("YubiKey ausschalten"))
        if not secret:
            if forced:
                self._relock()
            return
        pw, pin = secret
        fp = self.vault.identity.public().fp_raw()

        def done(_u):
            self.cfg.set_fido(fp, False)
            self._recovery_kf = self._recovery_secret = None
            self.after_unlock()
            messagebox.showinfo(_("YubiKey ausgeschaltet"), _("Die Identität ist wieder ohne YubiKey geschützt."))
        self.vault_op(_("Schalte YubiKey aus"), lambda v: v.unprotect(v.full_keys(pw, pin, kf)), done,
                      self._relock if forced else None)

    def unlock_recovery(self):
        """Entsperren mit Notfall-Paket (YubiKey verloren, defekt, PIN gesperrt)."""
        path = self.v_id.get()
        dlg = tk.Toplevel(self)
        dlg.title(_("Mit Notfall-Paket entsperren"))
        dlg.configure(background=self.pal["bg"])
        dlg.transient(self)
        dlg.grab_set()
        ttk.Label(dlg, wraplength=600, justify="left", text=(
            _("1. Auf der Seite „Start“ die Identitätsdatei wählen (die Schlüsseldatei kommt aus dem Paket).\n2. "
              "Hier Passphrase und App-PIN der Identität eintragen.\n3. Mindestens ZWEI Teile des Notfall-Pakets "
              "einfügen (je Teil ein Absatz) oder die Teil-Dateien öffnen. Mit drei Teilen erkennt die App einen "
              "verfälschten Teil.\n\nDanach verlangt die App sofort ein NEUES Notfall-Paket – der alte "
              "Notfall-Code gilt als verbraucht.")
        )).pack(padx=14, pady=12, anchor="w")
        # Befund R11-M1: bei Modus 5 ist das Passphrase-Feld auf „Start“ ausgeblendet – deshalb eigene Felder hier
        v_pw, v_pin = tk.StringVar(), tk.StringVar()
        g = ttk.Frame(dlg)
        g.pack(fill="x", padx=14, pady=(0, 8))
        ttk.Label(g, text=_("Passphrase:")).grid(row=0, column=0, sticky="w", padx=(0, 8))
        e_pw = ttk.Entry(g, textvariable=v_pw, show="•", width=50)
        e_pw.grid(row=0, column=1, sticky="we")
        ttk.Label(g, text=_("App-PIN:")).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(4, 0))
        ttk.Entry(g, textvariable=v_pin, show="•", width=20).grid(row=1, column=1, sticky="w", pady=(4, 0))
        g.columnconfigure(1, weight=1)

        def cleanup():
            v_pw.set("")
            v_pin.set("")
            set_text(t, "")
        dlg.cleanup = cleanup
        fr, t = scrolled_text(dlg, height=9, font=(MONO, 10), app=self)
        fr.pack(fill="both", expand=True, padx=14)

        def load():
            texts = []
            for p in filedialog.askopenfilenames(parent=dlg, filetypes=[(_("Notfall-Teil"), "*.sashare")]):
                try:
                    texts.append(self.share_to_text(read_file(p, 1024)))
                except (OSError, core.SigillumError):
                    return messagebox.showerror("Sigillum Arcanum", _("Nicht lesbar: {0}").format(p), parent=dlg)
            if texts:
                set_text(t, "\n\n".join(texts))

        def go():
            blocks = [b for b in re.split(r"\n[ \t]*\n", get_text(t).strip()) if b.strip()]
            try:
                kf, code_id, code = notfall.open_parts([bytes.fromhex("".join(b.split())) for b in blocks])
            except (ValueError, core.SigillumError) as e:
                return messagebox.showerror(_("Notfall-Paket"), str(e), parent=dlg)
            pw, pin = v_pw.get(), v_pin.get()
            cleanup()
            dlg.destroy()
            self._unlock_with_code(path, kf, code_id, code, pw, pin)
        row = ttk.Frame(dlg)
        row.pack(fill="x", padx=14, pady=12)
        ttk.Button(row, text=_("Teil-Dateien öffnen…"), command=load).pack(side="left")
        ttk.Button(row, text=_("Entsperren"), style="Primary.TButton", command=go).pack(side="right")
        ttk.Button(row, text=_("Abbrechen"), command=lambda: (cleanup(), dlg.destroy())).pack(side="right", padx=6)
        e_pw.focus_set()

    def _unlock_with_code(self, path, kf, code_id, code, pw, pin):

        def prepare():
            if not path:
                raise core.SigillumError(_("Bitte die Identitätsdatei wählen."))
            if not pw or not pin:
                raise core.SigillumError(_("Bitte Passphrase und PIN der Identität eintragen."))
            blob = read_file(path)
            if ratchet.file_mode(blob) != core.MODE_IDENTITY_FIDO:
                raise core.SigillumError(_("Diese Identität hat keinen YubiKey – normal entsperren."))
            return lambda: (ratchet.Vault.open(blob, pw, pin, kf, code=(code_id, code)), hashlib.sha256(blob).digest())

        def done(res):
            if not self._rollback_ok(res[0]):
                return self.set_status(_("Nicht geöffnet: ältere Fassung der Identitätsdatei."))
            self._adopt(res[0], res[1], path)
            self._recovery_kf = kf
            self._recovery_secret = (pw, pin)
            self.v_ipass.set("")
            self.v_ipin.set("")
            self.after_unlock()
            # Befund R4-2: sofort in der Datei vermerken – die Erneuerung wird auch nach einem Absturz verlangt
            self.vault_op(_("Vermerke Notfall"), lambda v: v.mark_recovery_used(), lambda _u: self._after_recovery(),
                          self._relock)
        self.run(_("Entsperre mit Notfall-Paket"), prepare, done)

    def _after_recovery(self):
        """Pflicht: verbrauchten Notfall-Code ersetzen. Abbruch = wieder sperren."""
        dlg = tk.Toplevel(self)
        dlg.title(_("Notfall-Code verbraucht – neues Paket nötig"))
        dlg.configure(background=self.pal["bg"])
        dlg.transient(self)
        dlg.grab_set()
        choice = {"v": None}
        ttk.Label(dlg, wraplength=540, justify="left", text=(
            _("Die Identität ist mit dem Notfall-Paket entsperrt. Der Notfall-Code gilt jetzt als verbraucht – es "
              "muss SOFORT ein neues Paket entstehen. Danach die alten Papiere vernichten.\n\nWie geht es weiter?"))
        ).pack(padx=14, pady=12, anchor="w")
        for key, text in (("keep", _("Bisherigen YubiKey behalten (Key ist da, nur nicht zur Hand gewesen)")),
                          ("new", _("Neuen YubiKey einrichten (alter Key verloren oder defekt)")),
                          ("off", _("YubiKey ausschalten"))):
            ttk.Button(dlg, text=text, command=lambda k=key: (choice.update(v=k), dlg.destroy())).pack(
                fill="x", padx=14, pady=3)
        ttk.Button(dlg, text=_("Abbrechen – Identität wieder sperren"), style="Danger.TButton",
                   command=dlg.destroy).pack(fill="x", padx=14, pady=(12, 14))
        self.wait_window(dlg)
        if choice["v"] is None or not self.vault:
            return self._relock()
        if choice["v"] == "off":
            return self.fido_disable(forced=True)
        self._fido_setup(choice["v"], forced=True)

    def _fido_setup(self, how, forced, secret=None, kf=None, on_done=None):
        """how = "new" (neuen Zugang anlegen) oder "keep" (vorhandenen Key antippen). Erzeugt immer ein neues
        Notfall-Paket und würfelt den Dateischlüssel neu. Erst nach Bestätigung wird gespeichert.
        Verlangt den Nachweis ALLER Faktoren (Passphrase + PIN + Schlüsseldatei), v11."""
        def abort(msg):
            if forced:
                self._relock()
            if msg:
                messagebox.showerror("YubiKey", msg)
        if not self.vault:                                     # Befund R11-M2: zwischenzeitlich gesperrt
            return abort(_("Bitte zuerst deine Identität entsperren (Seite „Start“)."))
        try:
            kf = self._identity_keyfile(kf)
        except core.SigillumError as e:
            return abort(str(e))
        secret = secret or self._secret_for_change(_("YubiKey / Notfall-Paket"))
        if not secret:
            return abort(None)
        pw, pin = secret
        if how == "new" and not messagebox.askokcancel(
                "YubiKey", _("Gleich erscheint die Abfrage für den Sicherheitsschlüssel.\n\nNur den YubiKey "
                             "benutzen – im Windows-Dialog „Sicherheitsschlüssel“ wählen, NICHT Windows Hello und "
                             "NICHT Smartphone/Tablet.\n\nPIN eingeben und antippen; danach zur Kontrolle ein "
                             "zweites Mal.")):
            return abort(None)
        vault, cred_ids = self.vault, self.vault.fido_cred_ids()
        token = fidokey.Fido2Token(self.fido_ui())
        tag = secrets.token_hex(3).upper()

        def prepare():
            def work():
                full = vault.full_keys(pw, pin, kf)              # zuerst: falsche Passphrase -> nichts am Key tun
                salt = vault.new_prf_salt()
                key = token.enroll(salt) if (how == "new" or not cred_ids) else token.derive(cred_ids, salt)
                code = vault.new_code()
                parts = notfall.build(kf, *code)
                if not notfall.verify_all_pairs(parts, kf, *code):
                    raise core.SigillumError(_("Kontrolle des Notfall-Pakets fehlgeschlagen – nichts geändert."))
                return salt, key, code, parts, full
            return work

        def built(res):
            salt, key, code, parts, full = res
            try:
                ok = self._hand_out_parts(parts, tag, _("Notfall-Paket"), pdfout.package_sheet,
                                          _("Passphrase und PIN der Identität"))
            except Exception as e:                          # R6-3: nie unvollständig weiterlaufen
                ok = False
                messagebox.showerror("Sigillum Arcanum", _("Unerwarteter Fehler ({0}).").format(type(e).__name__))
            if not ok:
                return abort(_("Abgebrochen – Notfall-Paket verworfen, nichts geändert."))
            fp = vault.identity.public().fp_raw()

            def done(_u):
                self.cfg.set_fido(fp, True)
                self._recovery_kf = self._recovery_secret = None
                self.after_unlock()
                messagebox.showinfo(
                    _("YubiKey aktiv"), _("Die Identität ist jetzt mit YubiKey geschützt (Notfall-Paket {0}).\n\n• "
                                       "Im Alltag: PIN + Schlüsseldatei + YubiKey – die Passphrase bleibt "
                                       "verschlossen.\n• Ein früheres Notfall-Paket ist ungültig – vernichten.\n• "
                                       "Den YubiKey abziehen, wenn er nicht gebraucht wird.\n\nAls Nächstes sucht "
                                       "die App nach älteren Kopien deiner Identitätsdatei.").format(tag))
                self.find_old_copies()
                if on_done:
                    on_done(True)

            def failed():
                messagebox.showwarning("YubiKey", _("Die Identität wurde NICHT umgestellt. Die gedruckten Papiere "
                                                    "des Pakets {0} sind damit wertlos – bitte vernichten.").format(tag))
                if forced:
                    self._relock()
            self.vault_op(_("Stelle Identität um"), lambda v: v.protect(salt, [key], code, full), done, failed)

        self.run(_("YubiKey: Zugang anlegen") if how == "new" else _("YubiKey: Key antippen"), prepare, built,
                 self._relock if forced else None)

    # ------------------------------------------------- Teile ausgeben (Befund R4-1: nie alle an einem Ort)
    @staticmethod
    def share_to_text(share: bytes) -> str:
        h = share.hex().upper()
        groups = [h[i:i + 4] for i in range(0, len(h), 4)]
        return "\n".join(" ".join(groups[i:i + 8]) for i in range(0, len(groups), 8))

    def _hand_out_parts(self, parts, tag, what, pdf_fn, secret_names) -> bool:
        """Druckt die Teile als PDFs in einen Ordner, löscht die PDFs nach Bestätigung des Drucks wieder und speichert
        auf Wunsch jeden Teil als Datei in einem EIGENEN Ordner. False = abgebrochen (alles Geschriebene gelöscht)."""
        folder = filedialog.askdirectory(title=_("{0} {1}: Ordner NUR zum Drucken (die PDFs werden danach gelöscht)").format(what, tag))
        if not folder or not self.confirm_local(folder):
            return False
        pdfs, files, q = [], [], None
        try:
            for i, part in enumerate(parts, 1):
                q = os.path.join(folder, f"{what.lower().replace(' ', '_').replace('-', '_')}_{tag}_{_('teil')}_{i}.pdf")
                if os.path.lexists(q):                  # nie eine fremde Datei überschreiben oder löschen
                    q = None
                    raise FileExistsError(_("Datei existiert bereits"))
                pdf_fn(q, self.share_to_text(part), i, len(parts), 2, tag)
                pdfs.append(q)
        except Exception as e:                          # R6-3: jeder Fehler -> nichts liegen lassen
            wipe(pdfs + ([q] if q else []))
            messagebox.showerror("Sigillum Arcanum", _("PDF nicht schreibbar ({0}) – alles gelöscht.").format(type(e).__name__))
            return False
        printed = messagebox.askyesno(
            _("{0} drucken").format(what),
            _("Die {0} PDFs liegen in:\n{1}\n\nJetzt auf einem LOKALEN Drucker drucken (keine "
              "Netzwerk-/Cloud-Drucker).\n\nDanach:\n• jedes Papier an einen EIGENEN Ort bringen (Zuhause, "
              "Schließfach, Vertrauensperson),\n• NIE zusammen mit {2} aufbewahren.\n\nGedruckt? „Ja“ löscht die "
              "PDFs jetzt. „Nein“ verwirft alles.").format(len(parts), folder, secret_names), icon="warning")
        if not printed:
            wipe(pdfs)
            return False
        if messagebox.askyesno(_("{0} – zusätzlich als Dateien?").format(what),
                               _("Jeden Teil zusätzlich als Datei sichern (z. B. auf drei verschiedenen "
                                 "USB-Sticks)?\n\nDann fragt die App für JEDEN Teil nach einem EIGENEN Ordner. "
                                 "Drei Teile im selben Ordner wären so gut wie gar kein Schutz und werden "
                                 "abgelehnt.\n\nNicht nötig, wenn die Papiere reichen.")):
            used = set()
            for i, part in enumerate(parts, 1):
                d = filedialog.askdirectory(title=_("{0} {1}: EIGENER Ordner für Teil {2} von {3}").format(what, tag, i, len(parts)))
                if not d or not self.confirm_local(d):
                    wipe(files + pdfs)
                    return False
                rd = os.path.normcase(os.path.realpath(d))
                if rd in used or rd == os.path.normcase(os.path.realpath(folder)):
                    wipe(files + pdfs)
                    messagebox.showerror("Sigillum Arcanum", _("Jeder Teil braucht einen EIGENEN Ordner, getrennt "
                                                               "vom Druckordner – abgebrochen, nichts gespeichert."))
                    return False
                if any(same_drive(d, u) for u in used) and not messagebox.askyesno(
                        _("Gleiches Laufwerk"), _("Teil {0} käme auf dasselbe Laufwerk wie ein anderer Teil. Wer "
                                               "dieses Laufwerk hat, hätte dann zwei Teile – also das ganze "
                                               "Paket.\n\nTrotzdem dort speichern?").format(i),
                        icon="warning"):
                    wipe(files + pdfs)
                    return False
                used.add(rd)
                p = os.path.join(d, f"{what.lower().replace(' ', '_').replace('-', '_')}_{tag}_{_('teil')}_{i}.sashare")
                try:
                    with open(p, "xb") as f:
                        f.write(part)
                    files.append(p)
                    if read_file(p, 1024) != part:
                        raise OSError(_("Kontrolle fehlgeschlagen"))
                except OSError as e:
                    wipe(files + pdfs)
                    messagebox.showerror("Sigillum Arcanum", _("Teil {0} nicht schreibbar: {1}").format(i, e))
                    return False
        left = wipe(pdfs)
        msg = _("Die PDFs wurden gelöscht.") if not left else (_("Diese PDFs ließen sich NICHT löschen – bitte von "
                                                               "Hand löschen:\n") + "\n".join(left))
        messagebox.showinfo(what, msg + (_("\n\nHinweis: Auf SSDs und in Cloud-Ordnern können gelöschte Dateien "
                                           "noch eine Zeit lang wiederherstellbar sein – deshalb BitLocker nutzen "
                                           "und nicht in OneDrive/Dropbox drucken.")))
        return True

    def print_only(self, title, filename, make_pdf) -> bool:
        """Ein PDF nur zum Drucken: in einen gewählten Ordner, nach Bestätigung überschreiben und löschen (R6-1)."""
        folder = filedialog.askdirectory(title=_("{0}: Ordner NUR zum Drucken (das PDF wird danach gelöscht)").format(title))
        if not folder or not self.confirm_local(folder):
            return False
        p = os.path.join(folder, filename)
        if os.path.lexists(p):                          # nie eine fremde Datei überschreiben oder löschen
            messagebox.showerror(title, _("Datei existiert bereits – nichts geändert:\n{0}").format(p))
            return False
        try:
            make_pdf(p)
        except Exception as e:
            wipe([p])
            messagebox.showerror(title, _("PDF nicht schreibbar ({0}) – nichts gespeichert.").format(type(e).__name__))
            return False
        printed = messagebox.askyesno(title, _("Das PDF liegt in:\n{0}\n\nJetzt auf einem LOKALEN Drucker "
                                               "drucken.\n\nGedruckt? „Ja“ löscht die PDF-Datei jetzt, „Nein“ "
                                               "verwirft sie ebenfalls.").format(p),
                                      icon="warning")
        left = wipe([p])
        if left:
            messagebox.showwarning(title, _("Die PDF-Datei ließ sich NICHT löschen – bitte von Hand: {0}").format(p))
        return printed

    # ------------------------------------------------- Alte Kopien (Befund R4-6)
    def find_old_copies(self):
        try:
            self.require_vault()
        except core.SigillumError as e:
            return messagebox.showerror("Sigillum Arcanum", str(e))
        folders = [os.path.dirname(os.path.abspath(self.vault_path))] if self.vault_path else []
        messagebox.showinfo(_("Alte Kopien suchen"), _("Die App sucht Kopien DIESER Identitätsdatei (auch ältere, z. "
                                                    "B. ohne YubiKey oder mit einem alten Notfall-Code). Sie "
                                                    "erkennt sie am Dateikopf, ohne etwas zu "
                                                    "entschlüsseln.\n\nGleich kannst du weitere Ordner wählen (z. "
                                                    "B. USB-Sticks, Dokumente, Backups). „Abbrechen“ beendet die "
                                                    "Auswahl."))
        while len(folders) < 12:
            d = filedialog.askdirectory(title=_("Weiteren Ordner durchsuchen (Abbrechen = fertig)"))
            if not d:
                break
            folders.append(d)
        hits = ratchet.find_copies(folders, self.vault.salt, self.vault_path)
        weak = [p for p in hits if ratchet.classify_copy(p, self.vault) == "weak"]
        same = [p for p in hits if p not in weak]
        note = (_("\n\nNicht durchsuchbar sind Versionsverläufe (OneDrive, Dropbox, Windows-Dateiversionsverlauf) "
                  "und fremde Geräte – dort bitte selbst löschen."))
        if same:
            note += (_("\n\n{0} Kopie(n) haben denselben Schutz wie die aktuelle Datei (ältere Sicherungen) und "
                       "bleiben erhalten:\n").format(len(same)) + "\n".join(same[:10]) + _("\nSie enthalten ältere "
                                                                          "Schlüsselstände; behalte höchstens "
                                                                          "eine aktuelle Sicherung an einem "
                                                                          "sicheren Ort."))
        if not weak:
            return messagebox.showinfo(_("Alte Kopien"), _("Keine schwächer geschützten Kopien gefunden.") + note)
        if not messagebox.askyesno(_("Schwächer geschützte Kopien gefunden"),
                                   _("{0} Kopie(n) dieser Identität öffnen sich OHNE YubiKey oder mit einem alten "
                                     "Key/Notfall-Code:\n\n").format(len(weak)) + "\n".join(weak[:15])
                                   + ("\n…" if len(weak) > 15 else "") + _("\n\nJetzt überschreiben und löschen?"),
                                   icon="warning"):
            return
        left = wipe(weak)
        messagebox.showinfo(_("Alte Kopien"), _("{0} Kopie(n) gelöscht.").format(len(weak) - len(left))
                            + (_("\n\nNicht löschbar:\n") + "\n".join(left) if left else "") + note)

    # ================================================= Hintergrund-Arbeit (Tk ist nicht threadsicher)
    def run(self, label, prepare, done, fail=None):
        if self.busy:
            if fail:
                fail()
            return
        try:
            work = prepare()
        except ERRORS as e:
            messagebox.showerror("Sigillum Arcanum", str(e))
            if fail:
                fail()
            return
        if work is None:
            return
        self.busy = True
        self.set_status(label + _(" … (Schlüsselableitung braucht einige Sekunden)"))
        self.configure(cursor="watch")
        box = {}

        def target():
            try:
                box["res"] = work()
            except ERRORS as e:
                box["err"] = str(e)
            except Exception as e:  # unerwartet: nur den Typ zeigen, keine Inhalte
                box["err"] = _("Unerwarteter Fehler: {0}").format(type(e).__name__)
            box["done"] = True

        threading.Thread(target=target, daemon=True).start()
        self._poll(box, done, fail)

    def _poll(self, box, done, fail=None):
        if not box.get("done"):
            self.after(60, lambda: self._poll(box, done, fail))
            return
        self.busy = False
        self._last_act = time.monotonic()              # lange Vorgänge zählen als Bedienung
        self.configure(cursor="")
        if box.get("err") == "EXTERN":
            self.lock(_("Identität gesperrt: Datei wurde außerhalb der App geändert."), force=True)
            messagebox.showerror("Sigillum Arcanum", _("Die Identitätsdatei wurde außerhalb dieses Fensters "
                                                       "geändert (zweites Fenster, Backup eingespielt?). Nichts "
                                                       "wurde gespeichert. Bitte neu entsperren."))
        elif box.get("err") == "EXTERN-QUICK":
            self._sealed = None
            self.refresh_start()
            messagebox.showerror("Sigillum Arcanum", _("Die Identitätsdatei wurde seit der Sperre außerhalb "
                                                       "dieses Fensters geändert. Die versiegelte Sitzung wurde "
                                                       "verworfen – bitte normal entsperren."))
        elif "err" in box:
            self.set_status(_("Fehler."))
            messagebox.showerror("Sigillum Arcanum", box["err"])
            if fail:
                fail()
        else:
            done(box["res"])

    def on_close(self):
        if self.busy and not messagebox.askyesno("Sigillum Arcanum", _("Es wird gerade gespeichert. Trotzdem "
                                                                       "schließen?")):
            return
        self.lock(force=True)
        self.clear_sensitive()
        self.destroy()


def main():
    try:
        core.self_test()
    except core.SigillumError as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Sigillum Arcanum", str(e))
        root.destroy()
        return
    App().mainloop()


if __name__ == "__main__":
    main()
