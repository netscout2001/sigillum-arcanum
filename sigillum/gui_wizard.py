"""Sigillum Arcanum – Assistenten und kleine Dialoge (v11, Baustein 3)."""
import hashlib
import os
import re
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import core, pdfout, ratchet
from .gui_base import (MONO, default_identity_dir, is_cloud, is_removable, read_file, removable_drives,
                       same_drive, write_new)
from .i18n import _


def _safe(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]", "_", name).strip("_")[:40]
    return s or _("identitaet")


class _Dialog(tk.Toplevel):
    def __init__(self, app, title):
        super().__init__(app)
        self.app = app
        self.title(title)
        self.configure(background=app.pal["bg"])
        self.transient(app)
        self.result = None
        self.body = ttk.Frame(self, padding=16)
        self.body.pack(fill="both", expand=True)

    def buttons(self, ok_text=None):
        r = ttk.Frame(self.body)
        r.pack(fill="x", pady=(12, 0))
        ttk.Button(r, text=ok_text or _("OK"), style="Primary.TButton", command=self._ok).pack(side="right")
        ttk.Button(r, text=_("Abbrechen"), command=self.destroy).pack(side="right", padx=6)
        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self.destroy())
        self.grab_set()

    def cleanup(self):
        """Beim Sperren: eingegebene Geheimnisse leeren (Befund R11-M3)."""
        for name in ("v_pw", "v_pin"):
            if hasattr(self, name):
                getattr(self, name).set("")


class FactorsDialog(_Dialog):
    """Passphrase + PIN der Identität (Schritt-Bestätigung)."""

    def __init__(self, app, title, text):
        super().__init__(app, title)
        ttk.Label(self.body, text=text, wraplength=460, justify="left").pack(anchor="w", pady=(0, 10))
        self.v_pw, self.v_pin = tk.StringVar(), tk.StringVar()
        g = ttk.Frame(self.body)
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)
        ttk.Label(g, text=_("Passphrase")).grid(row=0, column=0, sticky="w", pady=3, padx=(0, 10))
        e = ttk.Entry(g, textvariable=self.v_pw, show="•", width=50)
        e.grid(row=0, column=1, sticky="we")
        ttk.Label(g, text=_("PIN")).grid(row=1, column=0, sticky="w", pady=3, padx=(0, 10))
        ttk.Entry(g, textvariable=self.v_pin, show="•").grid(row=1, column=1, sticky="we")
        self.buttons(_("Bestätigen"))
        e.focus_set()

    def _ok(self):
        if not self.v_pw.get() or not self.v_pin.get():
            return messagebox.showerror("Sigillum Arcanum", _("Bitte Passphrase und PIN eingeben."), parent=self)
        self.result = (self.v_pw.get(), self.v_pin.get())
        self.v_pw.set("")
        self.v_pin.set("")
        self.destroy()


class PartnerImportDialog(_Dialog):
    """Vorhandenen gemeinsamen Schlüssel übernehmen: Name, Schlüsseldatei, Passphrase, PIN."""

    def __init__(self, app):
        super().__init__(app, _("Partner übernehmen"))
        ttk.Label(self.body, wraplength=500, justify="left", text=(
            _("Trage die Faktoren des gemeinsamen Schlüssels ein (z. B. vom Übergabeblatt und dem USB-Stick "
              "deines Partners). Sie werden verschlüsselt in deiner Identität gespeichert."))).pack(anchor="w", pady=(0, 10))
        self.v_name, self.v_kf, self.v_pw, self.v_pin = (tk.StringVar() for _u in range(4))
        g = ttk.Frame(self.body)
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)
        for i, (label, var, secret) in enumerate(((_("Name des Partners"), self.v_name, False),
                                                  (_("Schlüsseldatei"), self.v_kf, False),
                                                  (_("Passphrase"), self.v_pw, True), (_("PIN"), self.v_pin, True))):
            ttk.Label(g, text=label).grid(row=i, column=0, sticky="w", pady=3, padx=(0, 10))
            ttk.Entry(g, textvariable=var, show="•" if secret else "", width=50).grid(row=i, column=1, sticky="we")
        ttk.Button(g, text=_("Wählen…"), command=lambda: self.v_kf.set(
            filedialog.askopenfilename(parent=self, filetypes=[(_("Schlüsseldatei"), "*.sakey")]) or self.v_kf.get())
        ).grid(row=1, column=2, padx=(8, 0))
        self.buttons(_("Übernehmen"))

    def _ok(self):
        if not all(v.get() for v in (self.v_name, self.v_kf, self.v_pw, self.v_pin)):
            return messagebox.showerror("Sigillum Arcanum", _("Bitte alle Felder ausfüllen."), parent=self)
        self.result = (self.v_name.get(), self.v_kf.get(), self.v_pw.get(), self.v_pin.get())
        self.v_pw.set("")
        self.v_pin.set("")
        self.destroy()


class Wizard(tk.Toplevel):
    """Schritt-für-Schritt-Assistent. Ein Schritt = (Titel, build(frame), next() -> True/False/None, back_ok).
    next() gibt None zurück, wenn er selbst asynchron weiterschaltet (self.advance())."""

    def __init__(self, app, title):
        super().__init__(app)
        self.app = app
        self.title(title)
        self.configure(background=app.pal["bg"])
        self.transient(app)
        self.geometry("760x600")
        self.minsize(680, 520)
        self.i = 0
        head = ttk.Frame(self, style="Head.TFrame", padding=(18, 12))
        head.pack(fill="x")
        self.l_step = ttk.Label(head, text="", style="AppTitle.TLabel")
        self.l_step.pack(anchor="w")
        self.pb = ttk.Progressbar(head, maximum=len(self.steps()), length=300)
        self.pb.pack(anchor="w", pady=(6, 0))
        self.body = ttk.Frame(self, padding=(18, 14))
        self.body.pack(fill="both", expand=True)
        foot = ttk.Frame(self, padding=(18, 10))
        foot.pack(fill="x")
        self.b_next = ttk.Button(foot, text=_("Weiter"), style="Primary.TButton", command=self.next)
        self.b_next.pack(side="right")
        self.b_back = ttk.Button(foot, text=_("Zurück"), command=self.back)
        self.b_back.pack(side="right", padx=6)
        ttk.Button(foot, text=_("Abbrechen"), command=self.cancel).pack(side="left")
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.goto(0)
        self.lift()

    def steps(self):
        raise NotImplementedError

    def goto(self, i):
        self.i = i
        for w in self.body.winfo_children():
            w.destroy()
        title, build, _u, back_ok = self.steps()[i]
        n = len(self.steps())
        self.l_step.configure(text=_("Schritt {0} von {1}: {2}").format(i + 1, n, title))
        self.pb.configure(value=i + 1)
        build(self.body)
        self.b_back.configure(state="normal" if (i > 0 and back_ok) else "disabled")
        self.b_next.configure(text=_("Fertig") if i == n - 1 else _("Weiter"))

    def text(self, parent, s, style="TLabel"):
        ttk.Label(parent, text=s, style=style, wraplength=700, justify="left").pack(anchor="w", pady=(0, 8))

    def next(self):
        if self.app.busy:
            return messagebox.showinfo(_("Bitte warten"), _("Ein Vorgang läuft noch."), parent=self)
        r = self.steps()[self.i][2]()
        if r:
            self.advance()

    def advance(self):
        if self.i + 1 >= len(self.steps()):
            self.finish()
        else:
            self.goto(self.i + 1)

    def back(self):
        if self.i > 0:
            self.goto(self.i - 1)

    def cancel(self):
        if messagebox.askyesno(_("Assistent abbrechen"), _("Assistent wirklich abbrechen? Bereits Erzeugtes bleibt "
                                                        "bestehen."), parent=self):
            self.cleanup()
            self.destroy()

    def finish(self):
        self.cleanup()
        self.destroy()

    def cleanup(self):
        pass


class SetupWizard(Wizard):
    """Ersteinrichtung: Begrüßung + 8 Schritte (Baustein 3)."""

    def __init__(self, app):
        self.s = {"id_dir": tk.StringVar(value=default_identity_dir()),
                  "kf_dir": tk.StringVar(value=(removable_drives() or [""])[0]),
                  "name": tk.StringVar(), "pw": core.generate_passphrase(7), "kf": None, "backup": False,
                  "fido": False, "created": False}
        super().__init__(app, _("Einrichtung – Sigillum Arcanum"))

    def steps(self):
        return [(_("Willkommen"), self.b_welcome, lambda: True, True),
                (_("Speicherorte"), self.b_places, self.n_places, True),
                (_("Name und Schlüsseldatei"), self.b_name, self.n_name, True),
                (_("Passphrase"), self.b_pw, self.n_pw, False),
                (_("App-PIN"), self.b_pin, self.n_pin, True),
                (_("Identität erzeugen"), self.b_create, self.n_create, True),
                (_("Backup drucken"), self.b_backup, self.n_backup, False),
                (_("YubiKey (optional)"), self.b_fido, self.n_fido, True),
                (_("Kontakte vorbereiten"), self.b_contacts, lambda: True, True)]

    # ---------------------------------------------------------- Schritte
    def b_welcome(self, f):
        self.text(f, _("Dieser Assistent richtet deine Identität ein. Du brauchst etwa 15 Minuten, einen "
                       "USB-Stick, einen LOKALEN Drucker und Papier."), "HeadBg.TLabel")
        self.text(f, _("Was entsteht – und wo es hingehört:\n• Schlüsseldatei (256 Bit Zufall) → USB-Stick\n• "
                       "Passphrase (7 Wörter) → auf Papier, verschlossen; mit YubiKey nur für den Notfall\n• "
                       "App-PIN (mindestens 6 Zeichen) → im Kopf\n• Identitätsdatei → lokaler Ordner auf diesem "
                       "Rechner (nicht OneDrive/Dropbox)\n• Backup der Schlüsseldatei → 3 Papiere an 3 getrennten "
                       "Orten\n• optional YubiKey → dann Alltag ohne Passphrase, Notfall-Paket auf 3 Papieren"))
        self.text(f, _("Jeder Schritt erklärt kurz, wozu er dient. Bereits Erzeugtes wird nie überschrieben."),
                  "MutedBg.TLabel")

    def b_places(self, f):
        self.text(f, _("Die Schlüsseldatei ist ein Faktor, den du BESITZT – sie gehört getrennt von der "
                       "Identitätsdatei auf einen USB-Stick. Liegen beide im selben Ordner oder in der Cloud, ist "
                       "dieser Schutz weg."))
        drives = removable_drives()
        self.text(f, (_("Erkannte USB-Sticks: {0}").format(", ".join(drives))) if drives else
                  _("Kein USB-Stick erkannt (die Erkennung geht nur unter Windows) – bitte einen Ordner auf dem "
                    "Stick wählen."), "MutedBg.TLabel")
        g = ttk.Frame(f)
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)
        for i, (label, key) in enumerate(((_("Ordner für die Identitätsdatei (lokal)"), "id_dir"),
                                          (_("Ordner für die Schlüsseldatei (USB-Stick)"), "kf_dir"))):
            ttk.Label(g, text=label).grid(row=i, column=0, sticky="w", pady=4, padx=(0, 10))
            ttk.Entry(g, textvariable=self.s[key]).grid(row=i, column=1, sticky="we")
            ttk.Button(g, text=_("Wählen…"), command=lambda k=key: self.s[k].set(
                filedialog.askdirectory(parent=self) or self.s[k].get())).grid(row=i, column=2, padx=(8, 0))

    def n_places(self):
        idd, kfd = self.s["id_dir"].get().strip(), self.s["kf_dir"].get().strip()
        if not idd or not kfd:
            return messagebox.showerror(_("Speicherorte"), _("Bitte beide Ordner angeben."), parent=self)
        try:
            os.makedirs(idd, exist_ok=True)
        except OSError as e:
            return messagebox.showerror(_("Speicherorte"), _("Ordner nicht anlegbar: {0}").format(e), parent=self)
        if not os.path.isdir(kfd):
            return messagebox.showerror(_("Speicherorte"), _("Der Ordner für die Schlüsseldatei existiert nicht."),
                                        parent=self)
        if os.path.normcase(os.path.realpath(idd)) == os.path.normcase(os.path.realpath(kfd)):
            return messagebox.showerror(_("Speicherorte"), _("Identitätsdatei und Schlüsseldatei dürfen NICHT im "
                                                          "selben Ordner liegen – sonst hat jeder, der den Ordner "
                                                          "kopiert, beide."), parent=self)
        for path, what in ((idd, _("Der Ordner für die Identitätsdatei")), (kfd, _("Der Ordner für die Schlüsseldatei"))):
            if is_cloud(path) and not messagebox.askyesno(
                    _("Cloud-Ordner"), _("{0} liegt in einem synchronisierten "
                                      "Cloud-Ordner:\n{1}\n\nDer Anbieter hätte eine Kopie, alte Versionen "
                                      "bleiben erhalten. Dringend abgeraten.\n\nTrotzdem verwenden?").format(what, path), icon="warning", parent=self):
                return False
        if same_drive(idd, kfd) and not is_removable(kfd) and not messagebox.askyesno(
                _("Gleiches Laufwerk"), _("Beide Ordner liegen auf demselben Laufwerk. Wer den Rechner hat, hat dann "
                                       "beide Faktoren. Empfohlen: Schlüsseldatei auf einen "
                                       "USB-Stick.\n\nTrotzdem fortfahren?"), icon="warning",
                parent=self):
            return False
        return True

    def b_name(self, f):
        self.text(f, _("Der Name erscheint bei deinen Kontakten (1–64 Zeichen, keine Mischung von Schriften). "
                       "Danach erzeugt die App die Schlüsseldatei direkt auf dem USB-Stick."))
        r = ttk.Frame(f)
        r.pack(fill="x")
        ttk.Label(r, text=_("Name")).pack(side="left", padx=(0, 10))
        e = ttk.Entry(r, textvariable=self.s["name"], width=30)
        e.pack(side="left")
        e.focus_set()
        if self.s["kf"]:
            self.text(f, _("Schlüsseldatei bereits erzeugt: {0}").format(self.s['kf_path']), "MutedBg.TLabel")

    def n_name(self):
        try:
            name = core._check_name(self.s["name"].get())
        except core.SigillumError as e:
            return messagebox.showerror(_("Name"), str(e), parent=self)
        if self.s["kf"]:
            self.s["name_ok"] = name
            return True
        safe = _safe(name)
        id_path = os.path.join(self.s["id_dir"].get(), f"{safe}.said")
        kf_path = os.path.join(self.s["kf_dir"].get(), f"{safe}_{_('identitaet')}.sakey")
        for p in (id_path, kf_path):
            if os.path.lexists(p):
                return messagebox.showerror(_("Name"), _("Datei existiert bereits – wird nie "
                                                      "überschrieben:\n{0}\n\nAnderen Namen oder anderen Ordner "
                                                      "wählen.").format(p), parent=self)
        kf = core.new_keyfile()
        try:
            write_new(kf_path, kf)
            if read_file(kf_path, 1024) != kf:
                raise OSError(_("Kontrolle fehlgeschlagen"))
        except OSError as e:
            return messagebox.showerror(_("Schlüsseldatei"), _("Nicht schreibbar: {0}").format(e), parent=self)
        self.s.update(kf=kf, kf_path=kf_path, id_path=id_path, name_ok=name)
        return True

    def b_pw(self, f):
        self.text(f, _("Deine Passphrase: 7 zufällige Wörter (über 90 Bit). Eine KI kann sie nicht erraten. "
                       "Schreibe sie jetzt auf Papier und bewahre das Papier verschlossen auf – getrennt von "
                       "USB-Stick und Backup-Papieren. Mit YubiKey brauchst du sie nur im Notfall."))
        self.l_pw = ttk.Label(f, text=self.s["pw"], font=(MONO, 16, "bold"), wraplength=700)
        self.l_pw.pack(anchor="w", pady=8)
        ttk.Button(f, text=_("Neue Wörter erzeugen"), command=self._new_pw).pack(anchor="w")
        self.v_written = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text=_("Ich habe die Passphrase auf Papier geschrieben."), variable=self.v_written).pack(
            anchor="w", pady=(10, 4))
        self.text(f, _("Zur Kontrolle der Abschrift: Passphrase hier von deinem Papier abtippen (Groß/klein egal):"),
                  "MutedBg.TLabel")
        self.v_retype = tk.StringVar()
        ttk.Entry(f, textvariable=self.v_retype, font=(MONO, 12)).pack(fill="x")

    def _new_pw(self):
        self.s["pw"] = core.generate_passphrase(7)
        self.l_pw.configure(text=self.s["pw"])
        self.v_retype.set("")

    def n_pw(self):
        if not self.v_written.get():
            return messagebox.showerror(_("Passphrase"), _("Bitte erst auf Papier schreiben und das Häkchen setzen."),
                                        parent=self)
        if core.canonical_passphrase(self.v_retype.get()) != core.canonical_passphrase(self.s["pw"]):
            return messagebox.showerror(_("Passphrase"), _("Die Abschrift stimmt nicht – bitte Papier prüfen und "
                                                        "erneut abtippen."), parent=self)
        self.v_retype.set("")
        return True

    def b_pin(self, f):
        self.text(f, _("Die App-PIN brauchst du bei jedem Entsperren. Mindestens {0} Zeichen; empfohlen: 6 oder "
                       "mehr zufällige Ziffern (BSI TR-02102-1), mit YubiKey besser 8 oder mehr. Nicht "
                       "Geburtsdatum, nicht die YubiKey-PIN.").format(core.MIN_PIN))
        self.v_pin1, self.v_pin2 = tk.StringVar(), tk.StringVar()
        g = ttk.Frame(f)
        g.pack(anchor="w")
        for i, (label, var) in enumerate(((_("PIN"), self.v_pin1), (_("PIN wiederholen"), self.v_pin2))):
            ttk.Label(g, text=label).grid(row=i, column=0, sticky="w", pady=4, padx=(0, 10))
            ttk.Entry(g, textvariable=var, show="•", width=20).grid(row=i, column=1)
        # R14-N3: zufällige PIN vorschlagen (wird nur hier angezeigt, nie gespeichert)
        self.l_pin_hint = ttk.Label(f, text="", font=(MONO, 14, "bold"))
        ttk.Button(f, text=_("Zufällige 8-stellige PIN vorschlagen"), command=self._suggest_pin).pack(anchor="w", pady=(8, 2))
        self.l_pin_hint.pack(anchor="w")

    def _suggest_pin(self):
        p = core.generate_pin(8)
        self.v_pin1.set(p)
        self.v_pin2.set(p)
        self.l_pin_hint.configure(text=_("Vorschlag: {0}  – jetzt einprägen bzw. sicher notieren").format(p))

    def n_pin(self):
        a, b = self.v_pin1.get(), self.v_pin2.get()
        try:
            core.check_pin_new(a)                         # Befund R12-N2: keine naheliegende PIN
        except (core.SigillumError, ValueError) as e:
            return messagebox.showerror(_("PIN"), str(e), parent=self)
        if a != b:
            return messagebox.showerror(_("PIN"), _("Die beiden Eingaben unterscheiden sich."), parent=self)
        self.s["pin"] = a
        self.v_pin1.set("")
        self.v_pin2.set("")
        self.l_pin_hint.configure(text="")
        return True

    def b_create(self, f):
        if self.s["created"]:
            return self.text(f, _("Die Identität ist erzeugt und entsperrt."), "HeadBg.TLabel")
        self.text(f, _("Jetzt entsteht deine Identität (Schlüssel für Post-Quanten-Verschlüsselung und "
                       "-Signatur). Das dauert einige Sekunden."))
        self.text(f, _("Name: {0}\nIdentitätsdatei: {1}\nSchlüsseldatei: {2}").format(self.s.get('name_ok', ''), self.s.get('id_path', ''), self.s.get('kf_path', '')), "MutedBg.TLabel")

    def n_create(self):
        if self.s["created"]:
            return True
        app, s = self.app, self.s
        if app.v_pass.get() and core.canonical_passphrase(app.v_pass.get()) == core.canonical_passphrase(s["pw"]):
            return messagebox.showerror(_("Passphrase"), _("Diese Passphrase wird für einen gemeinsamen Schlüssel "
                                                        "benutzt – bitte neue Wörter erzeugen."), parent=self)

        def prepare():
            if os.path.lexists(s["id_path"]):
                raise core.SigillumError(_("Identitätsdatei existiert bereits – wird nicht überschrieben."))

            def work():
                v = ratchet.Vault.create(s["name_ok"], s["pw"], s["pin"], s["kf"])
                blob = v.to_blob()
                write_new(s["id_path"], blob)
                return v, hashlib.sha256(blob).digest()
            return work

        def done(res):
            v, h = res
            if app.vault is not None:
                app.lock(_("Bisherige Identität gesperrt."), force=True, keep=self)
            app._adopt(v, h, s["id_path"])
            d = core.keyfile_digest(s["kf"])
            app.cfg.note("identity_kf", d)
            app.cfg.set_paths(s["id_path"], s["kf_path"])
            app.v_id.set(s["id_path"])
            app.v_ikf.set(s["kf_path"])
            app.after_unlock()
            s["created"] = True
            self.advance()
        app.run(_("Erzeuge Identität"), prepare, done)
        return None

    def b_backup(self, f):
        self.text(f, _("Ohne Schlüsseldatei ist deine Identität verloren. Das Backup teilt sie in 3 Papiere – 2 "
                       "genügen, eines allein verrät nichts. Bringe sie an 3 getrennte Orte (Zuhause, "
                       "Schließfach, Vertrauensperson), nie zusammen mit der Passphrase."))
        ttk.Button(f, text=_("Backup jetzt drucken…"), style="Primary.TButton", command=self._backup).pack(anchor="w")
        self.l_backup = ttk.Label(f, text=_("Erledigt.") if self.s["backup"] else "", style="WarnBg.TLabel")
        self.l_backup.pack(anchor="w", pady=6)

    def _backup(self):
        def done(ok):
            self.s["backup"] = self.s["backup"] or ok
            if self.winfo_exists():
                self.l_backup.configure(text=_("Erledigt – Backup gedruckt.") if ok else _("Nicht erledigt."))
        self.app.split_keyfile(kf=self.s["kf"], on_done=done)
        self.lift()

    def n_backup(self):
        if self.s["backup"]:
            return True
        return messagebox.askyesno(_("Ohne Backup?"), _("Ohne Backup ist bei Verlust des USB-Sticks alles verloren. "
                                                     "Die Startseite erinnert dich daran.\n\nTrotzdem ohne Backup "
                                                     "weiter?"), icon="warning",
                                   parent=self)

    def b_fido(self, f):
        self.text(f, _("Mit einem YubiKey (FIDO2, z. B. YubiKey 5) öffnet sich deine Identität im Alltag mit PIN "
                       "+ Schlüsseldatei + YubiKey – die Passphrase bleibt verschlossen. Dazu entsteht ein "
                       "Notfall-Paket (3 Papiere) für den Fall, dass der Key verloren geht."))
        self.text(f, _("Vorher im Yubico Authenticator eine FIDO2-PIN setzen (6 zufällige Ziffern empfohlen). "
                       "Ohne YubiKey: einfach „Weiter“ – du kannst ihn später einschalten."), "MutedBg.TLabel")
        ttk.Button(f, text=_("YubiKey jetzt einschalten…"), style="Primary.TButton", command=self._fido).pack(anchor="w")
        self.l_fido = ttk.Label(f, text=_("Eingeschaltet.") if self.s["fido"] else "", style="WarnBg.TLabel")
        self.l_fido.pack(anchor="w", pady=6)

    def _fido(self):
        def done(ok):
            self.s["fido"] = True
            if self.winfo_exists():
                self.l_fido.configure(text=_("Eingeschaltet."))
        self.app.fido_enable(secret=(self.s["pw"], self.s["pin"]), kf=self.s["kf"], on_done=done)

    def n_fido(self):
        return True

    def b_contacts(self, f):
        self.text(f, _("Fertig eingerichtet. Damit dir jemand schreiben kann, tauschst du öffentliche Schlüssel "
                       "und verifiziert euch einmal persönlich oder per Video."), "HeadBg.TLabel")
        r = ttk.Frame(f)
        r.pack(anchor="w", pady=6)
        ttk.Button(r, text=_("Öffentlichen Schlüssel exportieren…"), command=self.app.export_pub).pack(side="left")
        ttk.Button(r, text=_("Fingerabdruck-Karte (PDF)…"), command=self.app.save_fp_card).pack(side="left", padx=8)
        ttk.Button(r, text=_("Kurzanleitung (PDF)…"), command=self.app.save_quick_guide).pack(side="left")
        self.text(f, _("Danach: Seite „Kontakte & Partner“ → Kontakt importieren → Verifizieren."), "MutedBg.TLabel")

    def finish(self):
        super().finish()
        self.app.refresh_all()
        self.app.show("start")

    def cleanup(self):
        for k in ("pw", "pin", "kf"):
            self.s[k] = None


class PartnerWizard(Wizard):
    """Gemeinsamen Schlüssel mit einem Partner einrichten (Variante C, Baustein 2/3)."""

    def __init__(self, app):
        self.s = {"name": tk.StringVar(), "kf": None, "pw": None, "pin": None, "saved": None, "printed": False}
        super().__init__(app, _("Partner einrichten – Sigillum Arcanum"))

    def steps(self):
        return [(_("Worum es geht"), self.b_intro, lambda: True, True),
                (_("Name des Partners"), self.b_name, self.n_name, True),
                (_("Schlüssel erzeugen"), self.b_gen, lambda: True, False),
                (_("Schlüsseldatei für den Partner"), self.b_stick, self.n_stick, True),
                (_("Übergabeblatt drucken"), self.b_sheet, self.n_sheet, True),
                (_("Deine Kopie"), self.b_own, self.n_own, True)]

    def b_intro(self, f):
        self.text(f, _("Ein gemeinsamer Schlüssel besteht aus Schlüsseldatei, Passphrase und PIN, die ihr beide habt."),
                  "HeadBg.TLabel")
        self.text(f, _("Für regelmäßigen Austausch sind Kontakt-Nachrichten sicherer: Einmal-Schlüssel je "
                       "Nachricht, echte Unterschrift je Person, nichts Geteiltes. Ein gemeinsamer Schlüssel ist "
                       "für Sonderfälle gedacht (z. B. Partner ohne eigene Identität)."))
        self.text(f, _("Du brauchst: einen USB-Stick für deinen Partner und einen lokalen Drucker. Übergib Stick "
                       "und Übergabeblatt persönlich."), "MutedBg.TLabel")

    def b_name(self, f):
        r = ttk.Frame(f)
        r.pack(anchor="w")
        ttk.Label(r, text=_("Name des Partners")).pack(side="left", padx=(0, 10))
        ttk.Entry(r, textvariable=self.s["name"], width=30).pack(side="left")

    def n_name(self):
        try:
            name = core._check_name(self.s["name"].get())
        except core.SigillumError as e:
            return messagebox.showerror(_("Name"), str(e), parent=self)
        if self.app.vault and any(core.name_skeleton(p[1]) == core.name_skeleton(name) for p in self.app.vault.partners()):
            return messagebox.showerror(_("Name"), _("Es gibt schon einen Partner mit (fast) gleichem Namen."), parent=self)
        self.s["name_ok"] = name
        if self.s["kf"] is None:
            self.s.update(kf=core.new_keyfile(), pw=core.generate_passphrase(7),
                          pin=core.generate_pin(6))
        return True

    def b_gen(self, f):
        self.text(f, _("Erzeugt – alles zufällig. Passphrase und PIN kommen gleich auf das Übergabeblatt."))
        ttk.Label(f, text=self.s["pw"], font=(MONO, 14, "bold"), wraplength=700).pack(anchor="w", pady=6)
        ttk.Label(f, text=_("PIN: {0}").format(self.s['pin']), font=(MONO, 14, "bold")).pack(anchor="w")

    def b_stick(self, f):
        self.text(f, _("Speichere die Schlüsseldatei auf den USB-Stick deines Partners (nicht in die Cloud)."))
        ttk.Button(f, text=_("Ordner auf dem USB-Stick wählen und speichern…"), style="Primary.TButton",
                   command=self._save_stick).pack(anchor="w")
        self.l_stick = ttk.Label(f, text=_("Gespeichert: {0}").format(self.s['saved']) if self.s["saved"] else "",
                                 style="MutedBg.TLabel")
        self.l_stick.pack(anchor="w", pady=6)

    def _save_stick(self):
        d = filedialog.askdirectory(parent=self, title=_("USB-Stick des Partners"))
        if not d:
            return
        if is_cloud(d) and not messagebox.askyesno(_("Cloud-Ordner"), _("Dieser Ordner liegt in einer Cloud – "
                                                                     "dringend abgeraten. Trotzdem?"), icon="warning", parent=self):
            return
        p = os.path.join(d, f"{_('gemeinsam')}_{_safe(self.s['name_ok'])}.sakey")
        try:
            write_new(p, self.s["kf"])
        except FileExistsError:
            return messagebox.showerror(_("Schlüsseldatei"), _("Datei existiert bereits – nichts überschrieben:\n{0}").format(p),
                                        parent=self)
        except OSError as e:
            return messagebox.showerror(_("Schlüsseldatei"), _("Nicht schreibbar: {0}").format(e), parent=self)
        self.s["saved"] = p
        self.l_stick.configure(text=_("Gespeichert: {0}").format(p))

    def n_stick(self):
        if not self.s["saved"]:
            return messagebox.showerror(_("Schlüsseldatei"), _("Bitte zuerst die Schlüsseldatei für den Partner "
                                                             "speichern."),
                                        parent=self)
        return True

    def b_sheet(self, f):
        self.text(f, _("Das Übergabeblatt enthält Passphrase und PIN. Die App löscht die PDF-Datei nach dem "
                       "Drucken. Übergib Blatt und Stick persönlich – am besten nicht in derselben Tasche."))
        ttk.Button(f, text=_("Übergabeblatt drucken…"), style="Primary.TButton", command=self._print).pack(anchor="w")
        self.l_sheet = ttk.Label(f, text=_("Gedruckt.") if self.s["printed"] else "", style="MutedBg.TLabel")
        self.l_sheet.pack(anchor="w", pady=6)

    def _print(self):
        tag = secrets.token_hex(3).upper()
        s = self.s
        ok = self.app.print_only(_("Übergabeblatt"), f"{_('uebergabe')}_{_safe(s['name_ok'])}_{tag}.pdf",
                                 lambda p: pdfout.partner_sheet(p, s["name_ok"], s["pw"], s["pin"], tag))
        s["printed"] = s["printed"] or ok
        if self.winfo_exists():
            self.l_sheet.configure(text=_("Gedruckt.") if s["printed"] else _("Nicht gedruckt."))
            self.lift()

    def n_sheet(self):
        if self.s["printed"]:
            return True
        return messagebox.askyesno(_("Ohne Übergabeblatt?"), _("Dann musst du Passphrase und PIN anders sicher "
                                                             "übergeben (nie per E-Mail, Messenger oder Telefon). "
                                                             "Trotzdem weiter?"), parent=self)

    def b_own(self, f):
        v = self.app.vault
        self.v_own = tk.StringVar(value="vault" if (v and v.fido) else "file")
        if v:
            ttk.Radiobutton(f, text=_("In meiner Identität speichern") + (_(" (empfohlen)") if v.fido else ""),
                            value="vault", variable=self.v_own).pack(anchor="w")
            if not v.fido:
                self.text(f, _("Deine Identität hat keinen YubiKey: Der gemeinsame Schlüssel hinge dann an deiner "
                               "Identitäts-Passphrase. Technisch gleich stark, aber alles an einer Stelle."),
                          "WarnBg.TLabel")
        else:
            self.text(f, _("Deine Identität ist gesperrt – du kannst den Schlüssel nur als Datei behalten (oder "
                           "vorher entsperren)."), "MutedBg.TLabel")
        ttk.Radiobutton(f, text=_("Als eigene Schlüsseldatei speichern (eigener USB-Stick)"), value="file",
                        variable=self.v_own).pack(anchor="w", pady=(6, 0))
        self.text(f, _("Bei „eigene Datei“ brauchst du Passphrase und PIN selbst – drucke dir dafür ein zweites "
                       "Übergabeblatt."), "MutedBg.TLabel")
        ttk.Button(f, text=_("Zweites Blatt für mich drucken…"), command=self._print).pack(anchor="w")

    def n_own(self):
        s, app = self.s, self.app
        d = core.keyfile_digest(s["kf"])
        if self.v_own.get() == "vault" and app.vault:
            def done(_u):
                app.cfg.note("shared_kf", d)
                app.refresh_partners()
                app.refresh_start()
                messagebox.showinfo(_("Partner eingerichtet"), _("„{0}“ ist in deiner Identität gespeichert. Beim "
                                                              "Schreiben und Lesen einfach den Partner wählen.").format(s['name_ok']))
                self.finish()
            app.vault_op(_("Speichere Partner"), lambda v: v.add_partner(s["name_ok"], s["kf"], s["pw"], s["pin"]), done)
            return None
        p = filedialog.asksaveasfilename(parent=self, defaultextension=".sakey",
                                         initialfile=f"{_('gemeinsam')}_{_safe(s['name_ok'])}_{_('meine')}.sakey",
                                         filetypes=[(_("Schlüsseldatei"), "*.sakey")])
        if not p:
            return False
        if is_cloud(p) and not messagebox.askyesno(_("Cloud-Ordner"), _("Dieser Ort liegt in einer Cloud – dringend "
                                                                     "abgeraten. Trotzdem?"), icon="warning", parent=self):
            return False
        try:
            write_new(p, s["kf"])
        except OSError as e:
            return messagebox.showerror(_("Schlüsseldatei"), _("Nicht schreibbar: {0}").format(e), parent=self)
        app.cfg.note("shared_kf", d)
        messagebox.showinfo(_("Partner eingerichtet"), _("Deine Schlüsseldatei: {0}\n\nBeim Schreiben „Gemeinsamer "
                                                      "Schlüssel von Hand“ wählen und Passphrase, PIN und diese "
                                                      "Datei eintragen.").format(p), parent=self)
        return True

    def cleanup(self):
        for k in ("kf", "pw", "pin"):
            self.s[k] = None
