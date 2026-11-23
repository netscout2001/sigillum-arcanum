"""Sigillum Arcanum – Seiten der Oberfläche (Start, Schreiben, Lesen, Kontakte & Partner, Schlüssel & Sicherheit,
Hand-Modus, Backup). Als Mixin in gui.App eingebunden."""
import hashlib
import os
import re
import secrets
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from . import codec, core, handmode, notfall, pdfout, ratchet, shamir
from .gui_base import (ERRORS, FONT, LOCK_CHOICES, MONO, clipboard_history_enabled, gap_text, get_text, is_cloud,
                       read_file, read_keyfile_path, same_folder, scrolled_text, set_text, wipe, write_atomic,
                       write_new)
from . import i18n
from .i18n import _

MANUAL = _("Von Hand (Felder unten)")


def card(parent, title, sub=None, fill="x", expand=False):
    outer = ttk.Frame(parent, style="Card.TFrame", padding=(14, 10))
    outer.pack(fill=fill, expand=expand, pady=(0, 10))
    ttk.Label(outer, text=title, style="Head.TLabel").pack(anchor="w")
    if sub:
        ttk.Label(outer, text=sub, style="Muted.TLabel", wraplength=860, justify="left").pack(anchor="w", pady=(2, 6))
    return outer


def row(parent):
    f = ttk.Frame(parent, style="Inner.TFrame")
    f.pack(fill="x", pady=3)
    return f


def page_title(parent, title, sub):
    ttk.Label(parent, text=title, style="Title.TLabel").pack(anchor="w")
    ttk.Label(parent, text=sub, style="MutedBg.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(2, 12))


class ScrollFrame(ttk.Frame):
    """Senkrecht scrollbarer Bereich (für lange Seiten)."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, background=app.pal["bg"], borderwidth=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(win, width=e.width))
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.inner.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.inner.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))
        app._canvases.append(self.canvas)

    def _wheel(self, e):
        self.canvas.yview_scroll(int(-e.delta / 120) or (-1 if e.delta > 0 else 1), "units")


class PagesMixin:
    _canvases = []

    # ================================================= Start
    def page_start(self, f):
        self._canvases = []
        page_title(f, _("Start"), _("Entsperren, Status und Einrichtung auf einen Blick."))
        self.v_pass, self.v_pin, self.v_kf = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.v_ipass, self.v_ipin = tk.StringVar(), tk.StringVar()
        self.v_id = tk.StringVar(value=self.cfg.d.get("last_id", ""))
        self.v_ikf = tk.StringVar(value=self.cfg.d.get("last_ikf", ""))
        self.v_show = tk.BooleanVar(value=False)
        self.v_qpin = tk.StringVar()
        self._secret_entries = []

        self.f_unlock = card(f, _("Identität entsperren"), _("Deine Identität öffnet Kontakte, Partner und das "
                                                           "Register des Hand-Modus. Mit YubiKey brauchst du im "
                                                           "Alltag keine Passphrase."))
        self.f_quick = ttk.Frame(self.f_unlock, style="Inner.TFrame")
        self.l_quick = ttk.Label(self.f_quick, text="", style="Warn.TLabel")
        self.l_quick.pack(anchor="w")
        r = row(self.f_quick)
        ttk.Label(r, text=_("App-PIN"), style="Card.TLabel", width=16).pack(side="left")
        e = self.e_qpin = ttk.Entry(r, textvariable=self.v_qpin, show="•", width=18)
        e.pack(side="left")
        e.bind("<Return>", lambda _e: self.quick_unlock())
        ttk.Button(r, text=_("Fortsetzen"), style="Primary.TButton", command=self.quick_unlock).pack(side="left", padx=8)
        ttk.Button(r, text=_("Normal entsperren"), command=self._discard_sealed).pack(side="left")

        grid = ttk.Frame(self.f_unlock, style="Inner.TFrame")
        grid.pack(fill="x", pady=(6, 0))
        grid.columnconfigure(1, weight=1)

        def line(r_, label, var, secret=False, pick=None):
            lab = ttk.Label(grid, text=label, style="Card.TLabel")
            lab.grid(row=r_, column=0, sticky="w", padx=(0, 10), pady=3)
            ent = ttk.Entry(grid, textvariable=var, show="•" if secret else "")
            ent.grid(row=r_, column=1, sticky="we", pady=3)
            btn = None
            if secret:
                self._secret_entries.append(ent)
            if pick:
                btn = ttk.Button(grid, text=_("Wählen…"), command=pick)
                btn.grid(row=r_, column=2, padx=(8, 0))
            ent.bind("<Return>", lambda _e: self.unlock())
            return lab, ent, btn

        line(0, _("Identitätsdatei"), self.v_id, pick=lambda: self._pick(self.v_id, _("Identität"), "*.said"))
        self.l_mode_hint = ttk.Label(grid, text="", style="Muted.TLabel")
        self.l_mode_hint.grid(row=1, column=1, sticky="w")
        self._pw_row = line(2, _("Passphrase"), self.v_ipass, True)
        self.e_ipin = line(3, _("PIN"), self.v_ipin, True)[1]
        line(4, _("Schlüsseldatei"), self.v_ikf, pick=lambda: self._pick(self.v_ikf, _("Schlüsseldatei"), "*.sakey"))
        r = row(self.f_unlock)
        ttk.Checkbutton(r, text=_("Eingaben anzeigen"), style="Card.TCheckbutton", variable=self.v_show,
                        command=self._toggle_show).pack(side="left")
        ttk.Button(r, text=_("Entsperren"), style="Primary.TButton", command=self.unlock).pack(side="right")
        ttk.Button(r, text=_("Notfall…"), command=self.unlock_recovery).pack(side="right", padx=8)
        self.v_id.trace_add("write", lambda *_u: self._update_mode_hint())

        self.f_open = card(f, _("Identität"))
        self.l_open = ttk.Label(self.f_open, text="", style="Card.TLabel", justify="left")
        self.l_open.pack(anchor="w")
        r = row(self.f_open)
        ttk.Button(r, text=_("Mein Fingerabdruck"), command=self.show_my_fp).pack(side="left")
        ttk.Button(r, text=_("Nachricht schreiben"), style="Primary.TButton",
                   command=lambda: self.show("write")).pack(side="left", padx=8)
        ttk.Button(r, text=_("Nachricht lesen"), command=lambda: self.show("read")).pack(side="left")

        self.f_state = card(f, _("Status und Hinweise"))
        self.l_state = ttk.Label(self.f_state, text="", style="Card.TLabel", justify="left", wraplength=880)
        self.l_state.pack(anchor="w")

        c = card(f, _("Einrichtung"))
        self.l_check = ttk.Label(c, text="", style="Card.TLabel", justify="left", font=(FONT, 10))
        self.l_check.pack(anchor="w")
        r = row(c)
        ttk.Button(r, text=_("Einrichtungs-Assistent…"), style="Primary.TButton",
                   command=self.start_wizard).pack(side="left")
        ttk.Button(r, text=_("Partner einrichten…"), command=self.start_partner_wizard).pack(side="left", padx=8)
        ttk.Button(r, text=_("Kurzanleitung speichern (PDF)…"), command=self.save_quick_guide).pack(side="left")
        self._update_mode_hint()

    def focus_unlock(self):
        """Cursor in das Feld setzen, das als Nächstes gebraucht wird."""
        if self.vault:
            return
        if self._sealed and self.f_quick.winfo_ismapped():
            return self.e_qpin.focus_set()
        pw_ent = self._pw_row[1]
        if pw_ent.winfo_ismapped() and not self.v_ipass.get():
            return pw_ent.focus_set()
        self.e_ipin.focus_set()

    def _discard_sealed(self):
        self._sealed = None
        self.v_qpin.set("")
        self.refresh_start()

    def _update_mode_hint(self):
        p = self.v_id.get()
        mode = None
        try:
            if p and os.path.isfile(p):
                with open(p, "rb") as fh:
                    mode = ratchet.file_mode(fh.read(16))           # nur den Kopf lesen
        except (OSError, core.SigillumError):
            mode = None
        lab, ent, _u = self._pw_row
        if mode == core.MODE_IDENTITY_FIDO:
            self.l_mode_hint.configure(text=_("Mit YubiKey geschützt: im Alltag nur PIN, Schlüsseldatei und "
                                              "YubiKey – die Passphrase bleibt verschlossen."))
            lab.grid_remove()
            ent.grid_remove()
        else:
            self.l_mode_hint.configure(text=_("Ohne YubiKey: Passphrase, PIN und Schlüsseldatei.") if mode else "")
            lab.grid()
            ent.grid()

    def refresh_start(self):
        if not hasattr(self, "f_open"):
            return
        v = self.vault
        if v:
            self.f_unlock.pack_forget()
            if not self.f_open.winfo_ismapped():
                self.f_open.pack(fill="x", pady=(0, 10), before=self.f_state)
            pub = v.identity.public()
            self.l_open.configure(text=f"{v.identity.name}  ·  " + (_("mit YubiKey") if v.fido else _("ohne YubiKey"))
                                  + _("\nFingerabdruck: {0}").format(pub.fingerprint()))
        else:
            self.f_open.pack_forget()
            if not self.f_unlock.winfo_ismapped():
                self.f_unlock.pack(fill="x", pady=(0, 10), before=self.f_state)
            self._update_mode_hint()
            if self._sealed:
                self.l_quick.configure(text=_("Automatisch gesperrt ({0}). Mit der App-PIN fortsetzen – noch {1} "
                                              "Versuch(e), danach normal entsperren.").format(self._sealed['name'], 3 - self._sealed['tries']))
                if not self.f_quick.winfo_ismapped():
                    self.f_quick.pack(fill="x", pady=(4, 8), after=self.f_unlock.winfo_children()[1])
            else:
                self.f_quick.pack_forget()
        self.l_state.configure(text="\n".join(self._warnings()) or _("Keine Hinweise."))
        self.l_check.configure(text=self._checklist())
        self._refresh_badge()

    def _warnings(self) -> list:
        out = []
        idp, ikf = self.v_id.get(), self.v_ikf.get()
        for p, what in ((idp, _("Identitätsdatei")), (ikf, _("Schlüsseldatei der Identität")),
                        (self.v_kf.get(), _("Schlüsseldatei (gemeinsam, von Hand)"))):
            if p and is_cloud(p):
                out.append(_("⚠ {0} liegt in einem Cloud-Ordner: {1}").format(what, p))
        if idp and ikf and same_folder(idp, ikf):
            out.append(_("⚠ Identitätsdatei und ihre Schlüsseldatei liegen im selben Ordner – Schlüsseldatei auf "
                         "einen USB-Stick legen."))
        if clipboard_history_enabled():
            out.append(_("⚠ Windows-Zwischenablage-Verlauf ist an – abschalten (Einstellungen > System > "
                         "Zwischenablage)."))
        v = self.vault
        if v:
            if v.fido and v.recovery_pending:
                out.append(_("⚠ Notfall-Paket wurde benutzt und noch nicht erneuert."))
            unver = [c.name for c, ok, _u in v.contacts() if not ok]
            if unver:
                out.append(_("• Noch nicht verifiziert: {0}").format(', '.join(unver[:5])) + (" …" if len(unver) > 5 else ""))
        if v:
            weakp = v.weak_partners()
            if weakp:
                out.append(_("⚠ Schwache Passphrase bei Partner ") + ", ".join(weakp[:5]) + _(" – gemeinsamen "
                                                                                             "Schlüssel neu "
                                                                                             "einrichten "
                                                                                             "(„Partner "
                                                                                             "einrichten…“) und "
                                                                                             "den alten entfernen."))
        if v and getattr(self, "_weak_pin", None):
            out.append(_("⚠ App-PIN ist naheliegend: {0} Eine neue PIN gibt es nur mit einer neuen Identität "
                         "(Einrichtungs-Assistent).").format(self._weak_pin))
        if self.cfg.ui("quick"):
            out.append(_("• Schnell-Entsperren mit PIN ist eingeschaltet (Seite „Schlüssel & Sicherheit“)."))
        return out

    def _checklist(self) -> str:
        v = self.vault
        idp, ikf = self.v_id.get(), self.v_ikf.get()
        has_id = bool(idp) and os.path.isfile(idp)
        places_ok = has_id and bool(ikf) and not is_cloud(idp) and not is_cloud(ikf) and not same_folder(idp, ikf)
        backup = False
        try:
            if ikf and os.path.isfile(ikf):
                backup = self.cfg.has("backup_kf", core.keyfile_digest(read_file(ikf, 1024)))
        except (OSError, core.SigillumError):
            pass
        fido = v.fido if v else (self._file_mode_of(idp) == core.MODE_IDENTITY_FIDO if has_id else False)
        exported = bool(v) and self.cfg.was_exported(v.identity.public().fp_raw())
        verified = bool(v) and (any(ok for _u, ok, _u in v.contacts()) or bool(v.partners()))
        items = [(has_id, _("Identität erzeugt")),
                 (places_ok, _("Speicherorte sicher (nicht in der Cloud, Schlüsseldatei getrennt)")),
                 (backup, _("Backup der Identitäts-Schlüsseldatei gedruckt")),
                 (fido, _("YubiKey eingeschaltet (optional, empfohlen)")),
                 (exported, _("Öffentlichen Schlüssel exportiert") + ("" if v else _(" (entsperren zum Prüfen)"))),
                 (verified, _("Erster Kontakt verifiziert oder Partner eingerichtet") + ("" if v else _(" (entsperren)")))]
        done = sum(1 for ok, _u in items if ok)
        return _("Einrichtung: {0} von {1} erledigt\n").format(done, len(items)) + "\n".join(
            ("✓  " if ok else "○  ") + t for ok, t in items)

    def save_quick_guide(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="sigillum_kurzanleitung.pdf",
                                         filetypes=[("PDF", "*.pdf")])
        if p:
            pdfout.quick_guide(p)
            self.set_status(_("Kurzanleitung gespeichert (enthält keine Geheimnisse): {0}").format(p))

    # ================================================= Schreiben
    def page_write(self, f):
        page_title(f, _("Nachricht schreiben"), _("Kontakt-Nachrichten sind der empfohlene Weg: Post-Quanten-sicher, "
                                               "signiert, neue Schlüssel mit jeder Nachricht (Einmal-Schlüssel)."))
        c = card(f, _("An wen?"))
        self.v_mode = tk.StringVar(value="contact")
        for val, text in (("contact", _("Kontakt (empfohlen)")), ("partner", _("Partner mit gespeichertem "
                                                                            "gemeinsamem Schlüssel")),
                          ("shared", _("Gemeinsamer Schlüssel von Hand"))):
            ttk.Radiobutton(c, text=text, value=val, variable=self.v_mode, style="Card.TRadiobutton").pack(anchor="w")
        self.f_recip = row(c)
        ttk.Label(self.f_recip, text=_("Empfänger"), style="Card.TLabel", width=16).pack(side="left")
        self.cb_recip = ttk.Combobox(self.f_recip, state="readonly", width=48)
        self.cb_recip.pack(side="left")
        self.f_partner_w = row(c)
        ttk.Label(self.f_partner_w, text=_("Partner"), style="Card.TLabel", width=16).pack(side="left")
        self.cb_partner = ttk.Combobox(self.f_partner_w, state="readonly", width=48)
        self.cb_partner.pack(side="left")
        self.f_manual_w = self._manual_fields(c)
        self.v_mode.trace_add("write", lambda *_u: self._mode_changed())

        c = card(f, _("Klartext"))
        fr, self.t_plain = scrolled_text(c, height=5, font=(FONT, 11), app=self)
        fr.pack(fill="both")
        r = row(c)
        self.v_latin = tk.BooleanVar(value=False)
        ttk.Checkbutton(r, text=_("Lateinische Umschrift statt Glyphen (z. B. für E-Mail)"), style="Card.TCheckbutton",
                        variable=self.v_latin).pack(side="left")
        ttk.Button(r, text=_("Verschlüsseln"), style="Primary.TButton", command=self.do_encrypt).pack(side="right")

        c = card(f, _("Geheimtext"), fill="both", expand=True)
        fr, self.t_cipher = scrolled_text(c, height=5, font=self.glyph_font, readonly=True, app=self)
        fr.pack(fill="both", expand=True)
        r = row(c)
        ttk.Button(r, text=_("Kopieren"), command=lambda: self.copy(get_text(self.t_cipher))).pack(side="left")
        ttk.Button(r, text=_("Als Textdatei speichern…"),
                   command=lambda: self.save_text(get_text(self.t_cipher))).pack(side="left", padx=8)
        ttk.Button(r, text=_("Als PDF zum Drucken…"), command=self.save_cipher_pdf).pack(side="left")
        self.l_enc_info = ttk.Label(r, text="", style="Muted.TLabel")
        self.l_enc_info.pack(side="right")
        self._mode_changed()

    def _manual_fields(self, parent):
        box = ttk.Frame(parent, style="Inner.TFrame")
        box.columnconfigure(1, weight=1)
        for i, (label, var, secret) in enumerate(((_("Passphrase"), self.v_pass, True), (_("PIN"), self.v_pin, True),
                                                  (_("Schlüsseldatei"), self.v_kf, False))):
            ttk.Label(box, text=label, style="Card.TLabel", width=16).grid(row=i, column=0, sticky="w", pady=2)
            e = ttk.Entry(box, textvariable=var, show="•" if secret else "")
            e.grid(row=i, column=1, sticky="we", pady=2)
            if secret:
                self._secret_entries.append(e)
        ttk.Button(box, text=_("Wählen…"), command=lambda: self._pick(self.v_kf, _("Schlüsseldatei"), "*.sakey")).grid(
            row=2, column=2, padx=(8, 0))
        ttk.Button(box, text=_("Felder leeren"), command=self.clear_shared).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(box, text=_("Der gemeinsame Schlüssel braucht EIGENE Faktoren – nie die deiner Identität. Tipp: "
                              "Partner in deiner Identität speichern (Seite „Kontakte & Partner“)."), style="Muted.TLabel",
                  wraplength=760).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        return box

    def _mode_changed(self):
        m = self.v_mode.get()
        for fr, key in ((self.f_recip, "contact"), (self.f_partner_w, "partner"), (self.f_manual_w, "shared")):
            if m == key:
                fr.pack(fill="x", pady=4)
            else:
                fr.pack_forget()

    def do_encrypt(self):
        text = get_text(self.t_plain)
        if not text.strip():
            return messagebox.showinfo("Sigillum Arcanum", _("Bitte zuerst einen Klartext eingeben."))
        self.note_plaintext(text)
        latin = self.v_latin.get()

        def show(blob):
            set_text(self.t_cipher, codec.encode(blob, latin))
            self.l_enc_info.configure(text=_("{0} Zeichen").format(len(codec.bytes_to_values(blob))))
            self.set_status(_("Verschlüsselt ({0:%H:%M:%S}).").format(datetime.now()))

        mode = self.v_mode.get()
        if mode == "shared":
            def prepare():
                pw, pin, kf, d = self.shared_factors()
                core.check_passphrase(pw)
                if not self.confirm_foreign_pw(pw):         # R14-N2
                    return None
                self.cfg.note("shared_kf", d)
                dev = self.cfg.channel_tag(d)
                return lambda: core.encrypt_shared(text, pw, pin, kf, dev)
            return self.run(_("Verschlüssele"), prepare, show)
        if mode == "partner":
            pid = self._partner_pid(self.cb_partner)
            if not pid:
                return messagebox.showinfo("Sigillum Arcanum", _("Bitte einen Partner wählen (Identität "
                                                                 "entsperren; Partner einrichten unter „Kontakte "
                                                                 "& Partner“)."))
            cfg = self.cfg

            def action(v):
                _u, pw, pin, kf = v.partner(pid)
                d = core.keyfile_digest(kf)
                blob = core.encrypt_shared(text, pw, pin, kf, cfg.channel_tag(d), stored=True)
                v.touch_partner(pid)
                return blob, d

            def done(res):
                self.cfg.note("shared_kf", res[1])
                show(res[0])
                self.refresh_partners()
            return self.vault_op(_("Verschlüssele"), action, done)
        fp = self._recip_fp()
        if not fp:
            return messagebox.showinfo("Sigillum Arcanum", _("Bitte einen Empfänger wählen (Identität entsperren)."))

        def show_pool(blob):
            show(blob)
            if ratchet.once_keys_left(self.vault, fp) == 0:            # Befund R12-N1
                self.set_status(_("Hinweis: Die Einmal-Schlüssel dieses Kontakts sind aufgebraucht. Bis er "
                                  "antwortet, gehen weitere Nachrichten an denselben Schlüssel (weniger "
                                  "Vorwärts-Sicherheit)."))
        self.vault_op(_("Verschlüssele"), lambda v: ratchet.encrypt(text, v, fp), show_pool)

    def _recip_fp(self):
        i = self.cb_recip.current()
        return self._recip_fps[i] if 0 <= i < len(self._recip_fps) else None

    def _partner_pid(self, cb):
        i = cb.current()
        ids = self._partner_ids if cb is self.cb_partner else [None] + self._partner_ids
        return ids[i] if 0 <= i < len(ids) else None

    def copy(self, s):
        self.clipboard_clear()
        self.clipboard_append(s)
        self.set_status(_("Geheimtext in die Zwischenablage kopiert."))

    def save_text(self, s):
        if not s:
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[(_("Text"), "*.txt")])
        if p:
            write_atomic(p, s.encode("utf-8"))
            self.set_status(_("Gespeichert: {0}").format(p))

    def save_cipher_pdf(self):
        s = get_text(self.t_cipher)
        if not s:
            return
        if not (0xE000 <= ord(s[0]) < 0xE080):
            s = codec.values_to_glyphs(codec.text_to_values(s))
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if p:
            pdfout.cipher_text(p, s)
            self.set_status(_("PDF gespeichert: {0}").format(p))

    # ================================================= Lesen
    def page_read(self, f):
        page_title(f, _("Nachricht lesen"), _("Mehrere Nachrichten durch eine Leerzeile trennen – die App sortiert sie."))
        c = card(f, _("Geheimtext"))
        r = row(c)
        ttk.Button(r, text=_("Einfügen"), command=self.paste_cipher).pack(side="left")
        ttk.Button(r, text=_("Dateien öffnen…"), command=self.open_cipher).pack(side="left", padx=8)
        fr, self.t_in = scrolled_text(c, height=5, font=self.glyph_font, app=self)
        fr.pack(fill="both", pady=4)
        r = row(c)
        ttk.Label(r, text=_("Gemeinsame Nachrichten öffnen mit"), style="Card.TLabel").pack(side="left")
        self.cb_rshared = ttk.Combobox(r, state="readonly", width=40)
        self.cb_rshared.pack(side="left", padx=8)
        self.cb_rshared.bind("<<ComboboxSelected>>", lambda _e: self._rshared_changed())
        ttk.Button(r, text=_("Entschlüsseln"), style="Primary.TButton", command=self.do_decrypt).pack(side="right")
        self.f_manual_r = self._manual_fields(c)

        c = card(f, _("Klartext"), fill="both", expand=True)
        fr, self.t_out = scrolled_text(c, height=6, font=(FONT, 11), readonly=True, app=self)
        fr.pack(fill="both", expand=True)
        r = row(c)
        self.l_dec_info = ttk.Label(r, text="", style="Muted.TLabel", wraplength=700, justify="left")
        self.l_dec_info.pack(side="left", fill="x", expand=True)
        ttk.Button(r, text=_("Klartext aus Fenster löschen"), command=self.clear_plain).pack(side="right")

    def _rshared_changed(self):
        if self.cb_rshared.current() <= 0:
            self.f_manual_r.pack(fill="x", pady=4)
        else:
            self.f_manual_r.pack_forget()

    def paste_cipher(self):
        try:
            set_text(self.t_in, self.clipboard_get())
        except tk.TclError:
            pass

    def open_cipher(self):
        texts = []
        for p in filedialog.askopenfilenames(filetypes=[(_("Text"), "*.txt"), (_("Alle Dateien"), "*.*")]):
            try:
                texts.append(read_file(p, codec.MAX_CHARS * 4).decode("utf-8").strip())
            except (OSError, UnicodeDecodeError, core.SigillumError):
                return messagebox.showerror("Sigillum Arcanum", _("Datei nicht lesbar: {0}").format(p))
        if texts:
            set_text(self.t_in, "\n\n".join(texts))

    def clear_plain(self):
        set_text(self.t_out, "")
        self.l_dec_info.configure(text="")

    def do_decrypt(self):
        self.clear_plain()
        blocks = [x for x in re.split(r"\n[ \t]*\n", get_text(self.t_in).strip()) if x.strip()]
        if not blocks:
            return messagebox.showinfo("Sigillum Arcanum", _("Bitte zuerst Geheimtext einfügen."))
        shared, items, errors = [], [], []
        for i, blk in enumerate(blocks, 1):
            try:
                blob = codec.decode(blk)
                mode = core.message_mode(blob)
                if mode == core.MODE_SHARED:
                    shared.append((i, blob))
                elif mode in ratchet.MODES:
                    items.append((i, blob))
                else:
                    raise core.SigillumError(_("Unbekannter Nachrichtentyp."))
            except ERRORS as e:
                errors.append({"index": i, "error": str(e)})
        if not shared and not items:
            return self.show_decrypted(errors, len(blocks))
        gen = self.vault_gen
        pid = self._partner_pid(self.cb_rshared)

        def prepare():
            f = own = d = None
            if shared:
                if pid:
                    self.require_vault()
                    _u, pw, pin, kf = self.vault.partner(pid)
                    d = core.keyfile_digest(kf)
                else:
                    pw, pin, kf, d = self.shared_factors()
                self.cfg.note("shared_kf", d)            # auch beim Entschlüsseln vermerken
                f = (pw, pin, kf)
                own = self.cfg.channel_tag(d)
            clone = None
            if items:
                self.require_vault()
                clone = self.vault.clone()
            save = self.save_work(clone) if clone else None

            def work():
                out = []
                for i, blob in shared:
                    try:
                        r = core.decrypt_shared(blob, *f)
                        out.append({"index": i, "result": r, "shared": True, "own": r["sender"] == own})
                    except core.SigillumError as e:
                        out.append({"index": i, "error": str(e)})
                if clone:
                    out += ratchet.process_batch(items, clone)
                return {"out": out, "clone": clone, "save": save}
            return work

        def done(res):
            out, clone = errors + res["out"], res["clone"]
            risky = [o for o in out if o.get("result", {}).get("risk")]
            if risky:
                lines = [_("• {0}: {1} fehlt").format(o['result']['sender_name'], gap_text(o['result'])) for o in risky[:10]]
                if len(risky) > 10:
                    lines.append(_("• … und {0} weitere").format(len(risky) - 10))
                if not messagebox.askyesno(
                        _("Nachricht fehlt"),
                        _("Es fehlen noch ältere Nachrichten:\n") + "\n".join(lines) + _("\n\nWenn du jetzt "
                                                                                       "fortfährst, werden die "
                                                                                       "Schlüssel dafür gelöscht "
                                                                                       "und diese Nachrichten "
                                                                                       "sind danach nicht mehr "
                                                                                       "lesbar.\n\nEmpfehlung: "
                                                                                       "NEIN wählen, die "
                                                                                       "fehlenden Nachrichten "
                                                                                       "suchen und alle zusammen "
                                                                                       "(durch Leerzeilen "
                                                                                       "getrennt) "
                                                                                       "einfügen.\n\nTrotzdem "
                                                                                       "fortfahren?"), icon="warning"):
                    self.set_status(_("Abgebrochen – nichts geändert, nichts gelöscht."))
                    return
            if not clone or not any("result" in o and not o.get("shared") for o in out):
                return self.show_decrypted(out, len(blocks))
            if gen != self.vault_gen:                   # Befund R11-M6: inzwischen gesperrt – nichts mehr speichern
                return messagebox.showwarning("Sigillum Arcanum", _("Die Identität wurde zwischenzeitlich "
                                                                    "gesperrt – nichts gespeichert, keine "
                                                                    "Schlüssel verbraucht."))

            def saved(h):
                if gen != self.vault_gen:
                    return messagebox.showwarning("Sigillum Arcanum", _("Die Identität wurde zwischenzeitlich "
                                                                        "gesperrt."))
                self.vault, self.vault_hash = clone, h
                self._note_gen()
                self.show_decrypted(out, len(blocks))
            self.run(_("Speichere Schlüsselstand"), lambda: res["save"], saved)
        self.run(_("Entschlüssele"), prepare, done)

    def show_decrypted(self, out, total):
        parts, ok = [], 0
        for o in out:
            if "result" in o:
                self.note_plaintext(o["result"]["text"])
            if "error" in o:
                parts.append(_("── Nachricht {0}: NICHT entschlüsselt ──\n{1}").format(o['index'], o['error']))
                continue
            r = o["result"]
            ok += 1
            ts = datetime.fromtimestamp(r["timestamp"]).strftime("%d.%m.%Y %H:%M")
            notes = []
            if o.get("shared"):
                von = _("gemeinsamer Schlüssel")
                if o.get("own"):
                    notes.append(_("ACHTUNG: stammt von DIESEM Gerät – dir zurückgeschickt?"))
                if self.cfg.seen_before(r["msgid"]):
                    notes.append(_("ACHTUNG: schon einmal geöffnet (Wiederholung?)"))
            else:
                von = _("{0} (Signaturen geprüft, Nr. {1})").format(r['sender_name'], r['sender_seq'])
                notes.append(_("{0}, {1} alte(r) Schlüssel gelöscht").format(r['key'], r['deleted']))
                if r.get("partner_reset"):
                    notes.append(_("Partner hat den Schlüsselwechsel neu gestartet"))
                if r.get("duplicate"):
                    notes.append(_("ACHTUNG: schon geöffnet – Wiederholung, nichts übernommen"))
                elif r.get("replay"):
                    notes.append(_("ACHTUNG: alte Erstnachricht erneut eingespielt – nichts übernommen"))
                if r.get("late"):
                    notes.append(_("verspätet eingetroffen – nichts übernommen"))
                if r.get("risk"):
                    notes.append(_("fehlend: {0} – aufgegeben").format(gap_text(r)))
            head = _("── Nachricht {0} · echt und unverändert · von {1} · {2}").format(o['index'], von, ts)
            parts.append(head + (" · " + " · ".join(notes) if notes else "") + " ──\n" + r["text"])
        set_text(self.t_out, "\n\n".join(parts))
        self.l_dec_info.configure(text=_("{0} von {1} Nachricht(en) entschlüsselt.").format(ok, total))
        self.set_status(_("Fertig."))
        if ok < total:
            messagebox.showwarning("Sigillum Arcanum", _("{0} Nachricht(en) konnten nicht entschlüsselt werden. "
                                                         "Details stehen im Klartext-Feld.").format(total - ok))

    # ================================================= Kontakte & Partner
    def page_contacts(self, f):
        page_title(f, _("Kontakte & Partner"), _("Kontakte tauschen öffentliche Schlüssel und verifizieren sich "
                                              "einmal persönlich. Partner teilen einen gemeinsamen Schlüssel."))
        c = card(f, _("Meine Visitenkarte"), _("Den öffentlichen Schlüssel darfst du offen weitergeben. Den "
                                            "Fingerabdruck liest du persönlich oder per Video vor."))
        r = row(c)
        ttk.Button(r, text=_("Öffentlichen Schlüssel exportieren…"), command=self.export_pub).pack(side="left")
        ttk.Button(r, text=_("Mein Fingerabdruck"), command=self.show_my_fp).pack(side="left", padx=8)
        ttk.Button(r, text=_("Fingerabdruck-Karte (PDF)…"), command=self.save_fp_card).pack(side="left")

        c = card(f, _("Kontakte"), _("Erst nach dem Verifizieren lässt die App Nachrichten in beide Richtungen zu."),
                 fill="both", expand=True)
        self.tv = ttk.Treeview(c, columns=("name", "fp", "ok"), show="headings", height=6)
        for col, w, h in (("name", 200, _("Name")), ("fp", 260, _("Fingerabdruck (Anfang)")), ("ok", 260, _("Verifiziert"))):
            self.tv.heading(col, text=h)
            self.tv.column(col, width=w)
        self.tv.pack(fill="both", expand=True, pady=4)
        r = row(c)
        ttk.Button(r, text=_("Kontakt importieren…"), style="Primary.TButton", command=self.import_contact).pack(side="left")
        ttk.Button(r, text=_("Verifizieren…"), command=self.verify_contact).pack(side="left", padx=8)
        ttk.Button(r, text=_("Schlüsselwechsel neu starten…"), command=self.reset_contact).pack(side="left")
        ttk.Button(r, text=_("Entfernen"), style="Danger.TButton", command=self.remove_contact).pack(side="right")

        c = card(f, _("Partner (gemeinsamer Schlüssel, in der Identität gespeichert)"),
                 _("Für Sonderfälle. Mit YubiKey empfohlen; ohne YubiKey hängt dann alles an einer Passphrase."),
                 fill="both", expand=True)
        self.tvp = ttk.Treeview(c, columns=("name", "created", "used"), show="headings", height=4)
        for col, w, h in (("name", 240, _("Partner")), ("created", 200, _("Angelegt")), ("used", 200, _("Zuletzt benutzt"))):
            self.tvp.heading(col, text=h)
            self.tvp.column(col, width=w)
        self.tvp.pack(fill="both", expand=True, pady=4)
        r = row(c)
        ttk.Button(r, text=_("Partner einrichten…"), style="Primary.TButton",
                   command=self.start_partner_wizard).pack(side="left")
        ttk.Button(r, text=_("Vorhandenen übernehmen…"), command=self.partner_import).pack(side="left", padx=8)
        ttk.Button(r, text=_("Entfernen"), style="Danger.TButton", command=self.partner_remove).pack(side="right")

    def export_pub(self):
        try:
            self.require_vault()
        except core.SigillumError as e:
            return messagebox.showerror("Sigillum Arcanum", str(e))
        pub = self.vault.identity.public()
        p = filedialog.asksaveasfilename(defaultextension=".sapub", initialfile=f"{pub.name}.sapub",
                                         filetypes=[(_("Öffentlicher Schlüssel"), "*.sapub")])
        if p:
            write_atomic(p, pub.to_bytes())
            self.cfg.note_exported(pub.fp_raw())
            self.refresh_start()
            messagebox.showinfo(_("Exportiert"), _("Diese Datei darfst du offen weitergeben.\n\nDanach liest du "
                                                "deinem Kontakt persönlich oder per Video deinen Fingerabdruck "
                                                "vor:\n\n{0}").format(pub.fingerprint()))

    def save_fp_card(self):
        if not self.vault:
            return messagebox.showerror("Sigillum Arcanum", _("Bitte zuerst deine Identität entsperren."))
        pub = self.vault.identity.public()
        p = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile=f"{_('fingerabdruck')}_{pub.name}.pdf",
                                         filetypes=[("PDF", "*.pdf")])
        if p:
            pdfout.fingerprint_card(p, pub.name, pub.fingerprint())
            self.set_status(_("Fingerabdruck-Karte gespeichert (nicht geheim): {0}").format(p))

    def show_my_fp(self):
        if not self.vault:
            return messagebox.showerror("Sigillum Arcanum", _("Bitte zuerst deine Identität entsperren."))
        messagebox.showinfo(_("Mein Fingerabdruck"), _("{0}\n\n{1}\n\nZum Vorlesen – persönlich oder per Video. Dein "
                                                    "Kontakt tippt ihn bei sich ein.").format(self.vault.identity.name, self.vault.identity.public().fingerprint()))

    def refresh_contacts(self):
        items = self.vault.contacts() if self.vault else []
        if hasattr(self, "tv"):
            self.tv.delete(*self.tv.get_children())
            for c, v, m in items:
                self.tv.insert("", "end", iid=c.fp(), values=(c.name, c.fingerprint()[:9] + " …",
                                                              _("ja ({0})").format(_(m)) if v else _("NEIN")))
        self._recip_fps = [c.fp() for c, v, m in items]
        if hasattr(self, "cb_recip"):
            self.cb_recip.configure(values=[f"{c.name}  [{c.fingerprint()[:9]}]" + ("" if v else _("  (unverifiziert)"))
                                            for c, v, m in items])
            self.cb_recip.set("")

    def refresh_partners(self):
        ps = self.vault.partners() if self.vault else []
        self._partner_ids = [p[0] for p in ps]

        def fmt(ts):
            return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M") if ts else "–"
        if hasattr(self, "tvp"):
            self.tvp.delete(*self.tvp.get_children())
            for pid, name, created, used in ps:
                self.tvp.insert("", "end", iid=pid, values=(name, fmt(created), fmt(used)))
        if hasattr(self, "cb_partner"):
            self.cb_partner.configure(values=[p[1] for p in ps])
            self.cb_partner.set(ps[0][1] if ps else "")
        if hasattr(self, "cb_rshared"):
            self.cb_rshared.configure(values=[MANUAL] + [p[1] for p in ps])
            self.cb_rshared.current(1 if ps else 0)
            self._rshared_changed()

    def import_contact(self):
        p = filedialog.askopenfilename(filetypes=[(_("Öffentlicher Schlüssel"), "*.sapub")])
        if not p:
            return
        try:
            self.require_vault()
            c = core.Contact.from_bytes(read_file(p, 8192))
        except ERRORS as e:
            return messagebox.showerror(_("Import fehlgeschlagen"), str(e))
        box = {}

        def action(v):
            box["same"] = v.add_contact(c)

        def done(_u):
            self.refresh_contacts()
            if self.tv.exists(c.fp()):
                self.tv.selection_set(c.fp())
            warn = ""
            if box.get("same"):
                warn = (_("\n\nACHTUNG: Es gibt bereits einen Kontakt namens '{0}' mit anderem Schlüssel. Prüfe "
                          "besonders sorgfältig, wer das ist.").format(c.name))
            messagebox.showinfo(_("Importiert"), _("'{0}' importiert, aber NICHT verifiziert.{1}\n\nNächster "
                                                "Schritt: 'Verifizieren…' – lass dir den Fingerabdruck persönlich "
                                                "oder per Video vorlesen.").format(c.name, warn))
        self.vault_op(_("Importiere Kontakt"), action, done)

    def _selected(self):
        sel = self.tv.selection()
        if not sel or not self.vault:
            messagebox.showinfo("Sigillum Arcanum", _("Bitte einen Kontakt auswählen."))
            return None
        c, _u = self.vault.contact(sel[0])
        return c

    def verify_contact(self):
        c = self._selected()
        if not c:
            return
        dlg = tk.Toplevel(self)
        dlg.title(_("{0} verifizieren").format(c.name))
        dlg.configure(background=self.pal["bg"])
        dlg.transient(self)
        dlg.grab_set()
        ttk.Label(dlg, wraplength=560, justify="left", text=(
            _("So prüfst du, dass die Datei wirklich von {0} stammt:\n\n1. Triff {1} persönlich – oder per "
              "Video-Anruf, und stelle eine Frage, die nur ihr beide beantworten könnt. Ein normaler Telefonanruf "
              "reicht NICHT: Stimmen lassen sich mit KI fälschen.\n2. {2} öffnet bei sich 'Mein Fingerabdruck' "
              "(oder zeigt die Fingerabdruck-Karte) und liest ihn vor.\n3. Tippe ihn hier vollständig ein (64 "
              "Zeichen, Leerzeichen egal).").format(c.name, c.name, c.name))).pack(padx=14, pady=12, anchor="w")
        v_m = tk.StringVar(value=ratchet.METHODS[0])
        f = ttk.Frame(dlg)
        f.pack(anchor="w", padx=14)
        for m in ratchet.METHODS:
            ttk.Radiobutton(f, text=_(m), value=m, variable=v_m).pack(side="left", padx=(0, 12))
        e = tk.Text(dlg, height=3, width=60, font=(MONO, 12), undo=False)
        self.register_text(e)
        e.pack(padx=14, pady=8)
        e.focus_set()

        def check():
            typed, method = e.get("1.0", "end-1c"), v_m.get()
            dlg.destroy()
            self.vault_op(_("Verifiziere"), lambda v: v.verify_contact(c.fp(), typed, method),
                          lambda _u: (self.refresh_contacts(), self.refresh_start(),
                                     messagebox.showinfo(_("Verifiziert"), _("{0} ist verifiziert ({1}).").format(c.name, _(method)))))
        r = ttk.Frame(dlg)
        r.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(r, text=_("Prüfen"), style="Primary.TButton", command=check).pack(side="right")
        ttk.Button(r, text=_("Abbrechen"), command=dlg.destroy).pack(side="right", padx=6)

    def reset_contact(self):
        c = self._selected()
        if not c or not messagebox.askyesno(
                _("Schlüsselwechsel neu starten"),
                _("Alle Wechselschlüssel für '{0}' werden sofort gelöscht. Deine nächste Nachricht an {1} startet "
                  "den Wechsel auf beiden Seiten neu.\n\nNur nötig, wenn Nachrichten nicht mehr zu entschlüsseln "
                  "sind (z. B. nach Einspielen eines Backups). Fortfahren?").format(c.name, c.name)):
            return
        self.vault_op(_("Setze zurück"), lambda v: ratchet.reset_contact(v, c.fp()),
                      lambda _u: messagebox.showinfo(_("Neu gestartet"), _("Schick {0} jetzt eine Nachricht.").format(c.name)))

    def remove_contact(self):
        c = self._selected()
        if c and messagebox.askyesno(_("Entfernen"), _("Kontakt '{0}' und alle Schlüssel für ihn entfernen?").format(c.name)):
            self.vault_op(_("Entferne"), lambda v: v.remove_contact(c.fp()), lambda _u: self.refresh_contacts())

    def partner_import(self):
        """Vorhandenen gemeinsamen Schlüssel (Schlüsseldatei + Passphrase + PIN) in die Identität übernehmen."""
        from .gui_wizard import PartnerImportDialog
        try:
            self.require_vault()
        except core.SigillumError as e:
            return messagebox.showerror("Sigillum Arcanum", str(e))
        if not self.vault.fido and not messagebox.askyesno(
                _("Ohne YubiKey"), _("Deine Identität ist NICHT mit einem YubiKey geschützt. Speicherst du den "
                                  "Partner darin, hängt der gemeinsame Schlüssel an deiner "
                                  "Identitäts-Passphrase.\n\nTechnisch gleich stark wie heute – aber wer deine "
                                  "Identität öffnet, hat auch diesen Schlüssel. Trotzdem speichern?"),
                icon="warning"):
            return
        dlg = PartnerImportDialog(self)
        self.wait_window(dlg)
        if not dlg.result:
            return
        name, path, pw, pin = dlg.result
        if not self.confirm_foreign_pw(pw):                # R14-N2
            return
        try:
            kf = read_keyfile_path(path, _("den Partner"))
        except core.SigillumError as e:
            return messagebox.showerror(_("Partner"), str(e))
        d = core.keyfile_digest(kf)
        if self.cfg.has("identity_kf", d):
            return messagebox.showerror(_("Partner"), _("Diese Schlüsseldatei schützt eine Identität – nie als "
                                                     "gemeinsamen Schlüssel verwenden."))

        def done(_u):
            self.cfg.note("shared_kf", d)
            self.refresh_partners()
            self.refresh_start()
            self.offer_wipe(path, _("die übernommene Schlüsseldatei"))
        self.vault_op(_("Speichere Partner"), lambda v: v.add_partner(name, kf, pw, pin), done)

    def offer_wipe(self, path, what):
        """Lose Kopie nach dem Übernehmen sicher löschen (sonst zwei Wege zum selben Geheimnis)."""
        cloud = is_cloud(path)
        if messagebox.askyesno(_("Lose Kopie löschen?"), _("Der Partner ist jetzt verschlüsselt in deiner Identität "
                                                         "gespeichert. Soll {0} jetzt überschrieben und gelöscht "
                                                         "werden?\n\n{1}\n\n").format(what, path)
                               + (_("ACHTUNG: Die Datei liegt in einem Cloud-Ordner – Versionen und Papierkorb "
                                    "dort bitte selbst leeren.\n\n") if cloud else "")
                               + _("Behalte sie nur, wenn du sie noch für ein anderes Gerät brauchst.")):
            left = wipe([path])
            messagebox.showinfo(_("Partner"), _("Gelöscht.") if not left else _("Ließ sich NICHT löschen: {0}").format(path))

    def partner_remove(self):
        sel = self.tvp.selection() if hasattr(self, "tvp") else ()
        if not sel or not self.vault:
            return messagebox.showinfo("Sigillum Arcanum", _("Bitte einen Partner auswählen."))
        name = self.vault.partner(sel[0])[0]
        if messagebox.askyesno(_("Partner entfernen"), _("Gemeinsamen Schlüssel mit '{0}' aus deiner Identität "
                                                      "entfernen? Nachrichten mit diesem Schlüssel lassen sich "
                                                      "danach nur noch mit den Faktoren von Hand öffnen.").format(name), icon="warning"):
            self.vault_op(_("Entferne Partner"), lambda v: v.remove_partner(sel[0]),
                          lambda _u: (self.refresh_partners(), self.refresh_start()))

    def start_wizard(self):
        from .gui_wizard import SetupWizard
        SetupWizard(self)

    def start_partner_wizard(self):
        from .gui_wizard import PartnerWizard
        PartnerWizard(self)

    # ================================================= Schlüssel & Sicherheit
    def _lang_changed(self):
        lang = i18n.LANGS[self.cb_lang.current()]
        if lang == self.cfg.ui("lang"):
            return
        self.cfg.set_ui("lang", lang)
        messagebox.showinfo("Sigillum Arcanum", "Die Sprache wechselt beim nächsten Start der App.\n\n"
                                                "The language changes the next time the app starts.")

    def page_keys(self, f):
        sf = ScrollFrame(f, self)
        sf.pack(fill="both", expand=True)
        f = sf.inner
        page_title(f, _("Schlüssel & Sicherheit"), _("Identität einrichten, YubiKey, automatische Sperre, Design, Sprache."))
        c = card(f, _("Neue Identität"), _("Der Einrichtungs-Assistent erledigt alles Schritt für Schritt: "
                                         "Speicherorte, Schlüsseldatei, Passphrase, PIN, Identität, Backup, "
                                         "YubiKey, Kontakte."))
        r = row(c)
        ttk.Button(r, text=_("Einrichtungs-Assistent starten…"), style="Primary.TButton",
                   command=self.start_wizard).pack(side="left")
        ttk.Label(c, text=_("Von Hand (für Fortgeschrittene) – nutzt die Felder auf der Seite „Start“:"),
                  style="Muted.TLabel").pack(anchor="w", pady=(8, 2))
        r = row(c)
        ttk.Label(r, text=_("Name"), style="Card.TLabel").pack(side="left")
        self.v_name = tk.StringVar()
        ttk.Entry(r, textvariable=self.v_name, width=20).pack(side="left", padx=6)
        ttk.Button(r, text=_("Identität erzeugen…"), command=self.new_identity).pack(side="left")
        ttk.Button(r, text=_("Neue Schlüsseldatei erzeugen…"), command=self.new_keyfile).pack(side="left", padx=8)
        r = row(c)
        ttk.Label(r, text=_("Passphrase"), style="Card.TLabel").pack(side="left")
        self.v_dice = tk.StringVar()
        ttk.Entry(r, textvariable=self.v_dice, font=(MONO, 11)).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(r, text=_("Erzeugen"), command=self.dice_passphrase).pack(side="left")
        ttk.Button(r, text=_("→ Identität"), command=lambda: self.v_ipass.set(self.v_dice.get())).pack(side="left", padx=4)
        ttk.Button(r, text=_("→ Gemeinsam"), command=lambda: self.v_pass.set(self.v_dice.get())).pack(side="left")

        c = card(f, _("YubiKey (optional, nur für deine Identität)"), _("Mit YubiKey: im Alltag PIN + "
                                                                       "Schlüsseldatei + YubiKey, die Passphrase "
                                                                       "nur im Notfall. Änderungen hier verlangen "
                                                                       "Passphrase und PIN."))
        self.l_fido = ttk.Label(c, text="", style="Card.TLabel", wraplength=860, justify="left")
        self.l_fido.pack(anchor="w", pady=(0, 4))
        r = row(c)
        ttk.Button(r, text=_("YubiKey einschalten…"), style="Primary.TButton", command=self.fido_enable).pack(side="left")
        ttk.Button(r, text=_("Notfall-Paket erneuern…"), command=self.fido_renew).pack(side="left", padx=8)
        ttk.Button(r, text=_("YubiKey ersetzen…"), command=self.fido_replace).pack(side="left")
        r = row(c)
        ttk.Button(r, text=_("Alte Kopien suchen…"), command=self.find_old_copies).pack(side="left")
        ttk.Button(r, text=_("YubiKey ausschalten…"), style="Danger.TButton", command=self.fido_disable).pack(side="right")

        c = card(f, _("Automatische Sperre"), _("Ohne Bedienung sperrt die App die Identität und leert alle "
                                             "Klartext- und Geheimnisfelder. Unter Windows sperrt sie zusätzlich, "
                                             "wenn der Bildschirm gesperrt wird."))
        r = row(c)
        ttk.Label(r, text=_("Sperren nach"), style="Card.TLabel").pack(side="left")
        self.cb_lock = ttk.Combobox(r, state="readonly", width=14, values=[_("{0} Minuten").format(m) for m in LOCK_CHOICES])
        self.cb_lock.current(LOCK_CHOICES.index(self.cfg.ui("lock_min")))
        self.cb_lock.bind("<<ComboboxSelected>>",
                          lambda _e: self.cfg.set_ui("lock_min", LOCK_CHOICES[self.cb_lock.current()]))
        self.cb_lock.pack(side="left", padx=8)
        ttk.Label(r, text=_("ohne Bedienung (Empfehlung: 10 Minuten)"), style="Muted.TLabel").pack(side="left")
        self.v_quick = tk.BooleanVar(value=self.cfg.ui("quick"))
        ttk.Checkbutton(c, text=_("Schnell-Entsperren: nach der automatischen Sperre genügt die App-PIN (solange "
                                  "die App läuft, höchstens 3 Versuche)"), style="Card.TCheckbutton", variable=self.v_quick,
                        command=self._quick_changed).pack(anchor="w", pady=(6, 0))
        ttk.Label(c, text=_("Standardmäßig AUS. Restrisiko: Die entsperrte Identität bleibt dann – mit der PIN "
                            "verschlüsselt – im Arbeitsspeicher; wer genau dann den Speicher ausliest, könnte die "
                            "kurze PIN durchprobieren. Gilt ab dem nächsten Entsperren."), style="Muted.TLabel",
                  wraplength=860, justify="left").pack(anchor="w")

        c = card(f, _("Design"))
        r = row(c)
        ttk.Button(r, text=_("Hell / Dunkel umschalten"), command=self.toggle_theme).pack(side="left")
        ttk.Label(r, text=_("Alle Farben erfüllen einen Kontrast von mindestens 4,5 : 1 (WCAG AA)."),
                  style="Muted.TLabel").pack(side="left", padx=10)

        c = card(f, "Sprache / Language")
        r = row(c)
        self.cb_lang = ttk.Combobox(r, state="readonly", width=14, values=["Deutsch", "English"])
        self.cb_lang.current(i18n.LANGS.index(self.cfg.ui("lang")) if self.cfg.ui("lang") in i18n.LANGS else 0)
        self.cb_lang.bind("<<ComboboxSelected>>", lambda _e: self._lang_changed())
        self.cb_lang.pack(side="left")
        ttk.Label(r, text="Gilt ab dem nächsten Start. / Takes effect after a restart.",
                  style="Muted.TLabel").pack(side="left", padx=10)

        c = card(f, _("Sicherheitshinweise"))
        ch = clipboard_history_enabled()
        lines = [
            (_("Zwischenablage-Verlauf"), _("AN – bitte abschalten (Einstellungen > System > Zwischenablage)") if ch
             else (_("aus") if ch is False else _("nur unter Windows prüfbar"))),
            (_("Netzwerk"), _("Die App baut keine Verbindung auf. Für höchste Sicherheit einen Offline-Rechner nutzen.")),
            (_("Größtes Risiko"), _("Schadsoftware auf dem Rechner sieht Klartext und Schlüssel – dagegen hilft "
                                   "keine Verschlüsselung.")),
            (_("Speicherorte"), _("Schlüsseldateien auf USB-Stick, Identitätsdatei lokal – nie in OneDrive/Dropbox. "
                               "Die App warnt bei Cloud-Ordnern.")),
            (_("Getrennte Faktoren"), _("Gemeinsamer Schlüssel und Identität brauchen verschiedene Schlüsseldateien "
                                     "und Passphrasen. Die App lehnt Überschneidungen ab.")),
            (_("Kontakte"), _("Nur persönlich oder per Video verifizieren – Telefonstimmen lassen sich mit KI fälschen.")),
            (_("Schlüsselwechsel"), _("Jede Kontakt-Nachricht kündigt einen neuen Empfangsschlüssel an; alte werden "
                                    "sofort gelöscht. Alte Nachrichten sind danach auch für dich nicht mehr "
                                    "lesbar – gewollt.")),
            (_("Arbeitsspeicher"), _("Python kann Schlüssel nicht garantiert löschen. App nach Gebrauch schließen.")),
            (_("Hand-Modus"), _("Jedes Blatt nur einmal, nur lokal drucken, danach vernichten.")),
            (_("Verfahren"), core.CRYPTO_SUMMARY + _(". Selbsttest beim Start bestanden.")),
        ]
        grid = ttk.Frame(c, style="Inner.TFrame")
        grid.pack(fill="x")
        for i, (k, v) in enumerate(lines):
            ttk.Label(grid, text=k, style="Head.TLabel").grid(row=i, column=0, sticky="nw", pady=4, padx=(0, 12))
            ttk.Label(grid, text=v, style="Card.TLabel", wraplength=640, justify="left").grid(row=i, column=1,
                                                                                              sticky="w", pady=4)

    def _quick_changed(self):
        self.cfg.set_ui("quick", bool(self.v_quick.get()))
        if not self.v_quick.get():
            self._quick = None
            self._sealed = None
        elif self.vault and not self._quick:
            # Der Schlüssel dafür entsteht aus der PIN beim Entsperren – die App merkt sich die PIN nicht
            messagebox.showinfo(_("Schnell-Entsperren"), _("Eingeschaltet. Es wirkt ab dem nächsten Entsperren: Erst "
                                                        "dann kennt die App die PIN, um die Sitzung bei einer "
                                                        "automatischen Sperre zu versiegeln."))
        self.refresh_start()
        self._refresh_badge()

    def new_keyfile(self):
        p = filedialog.asksaveasfilename(defaultextension=".sakey", filetypes=[(_("Schlüsseldatei"), "*.sakey")])
        if not p:
            return
        if is_cloud(p) and not messagebox.askyesno(_("Cloud-Ordner"), _("Der Speicherort liegt in einem "
                                                                     "Cloud-Ordner. Schlüsseldateien gehören auf "
                                                                     "einen USB-Stick.\n\nTrotzdem dort speichern?"), icon="warning"):
            return
        try:
            write_new(p, core.new_keyfile())
        except FileExistsError:
            return messagebox.showerror("Sigillum Arcanum", _("Datei existiert bereits – bestehende Schlüssel "
                                                              "werden nie überschrieben."))
        messagebox.showinfo(_("Schlüsseldatei erzeugt"), _("Gespeichert: {0}\n\nVerwende sie ENTWEDER für einen "
                                                         "gemeinsamen Schlüssel ODER für eine Identität, nie für "
                                                         "beides.\n\nOhne diese Datei ist nichts mehr zu "
                                                         "entschlüsseln. Lege jetzt ein Backup an (Seite "
                                                         "„Backup“).").format(p))

    def new_identity(self):
        name = self.v_name.get()
        p = filedialog.asksaveasfilename(defaultextension=".said", filetypes=[(_("Identität"), "*.said")])
        if not p:
            return

        def prepare():
            core._check_name(name)
            pw, pin, kf, d = self.identity_factors()
            if not self.was_generated(pw):                # Befund R12-M1: neue Identität nur mit gewürfelter Passphrase
                raise core.SigillumError(_("Für eine neue Identität die Passphrase bitte mit „Erzeugen“ würfeln "
                                           "lassen und mit „→ Identität“ übernehmen. Selbst ausgedachte "
                                           "Wortketten kann eine KI erraten, auch wenn sie aus Listenwörtern "
                                           "bestehen."))
            if os.path.exists(p):
                raise core.SigillumError(_("Datei existiert bereits – wird nicht überschrieben."))
            self.warn_cloud(p, _("Die neue Identitätsdatei"))

            def work():
                v = ratchet.Vault.create(name, pw, pin, kf)
                blob = v.to_blob()
                write_new(p, blob)
                return v, hashlib.sha256(blob).digest(), d
            return work

        def done(r):
            v, h, d = r
            self._adopt(v, h, p)
            self.v_id.set(p)
            self.cfg.note("identity_kf", d)
            self.cfg.set_paths(p, self.v_ikf.get())
            self.v_ipass.set("")
            self.v_ipin.set("")
            self.after_unlock()
            messagebox.showinfo(_("Identität erzeugt"), _("Geschützt mit den drei Identitäts-Faktoren und "
                                                        "entsperrt.\n\nDein Fingerabdruck zum Vorlesen:\n{0}").format(self.vault.identity.public().fingerprint()))
        self.run(_("Erzeuge Identität"), prepare, done)

    # ================================================= Backup
    def page_backup(self, f):
        page_title(f, _("Backup"), _("Schlüsseldateien in 3 Teile aufteilen (2 genügen). Für JEDE Schlüsseldatei ein "
                                  "eigenes Backup."))
        c = card(f, _("Backup anlegen"), _("Teile getrennt lagern: Zuhause, Schließfach, Vertrauensperson. Ein "
                                        "einzelner Teil verrät nichts. Die PDFs werden nach dem Drucken gelöscht."))
        r = row(c)
        ttk.Button(r, text=_("Schlüsseldatei wählen und Teile erzeugen…"), style="Primary.TButton",
                   command=self.split_keyfile).pack(side="left")
        c = card(f, _("Schlüsseldatei wiederherstellen"), _("Zwei Teile einfügen (Text aus dem PDF abtippen oder "
                                                          "Dateien öffnen), einen Teil pro Absatz – besser alle "
                                                          "drei: Dann erkennt die App einen falsch abgetippten "
                                                          "oder verfälschten Teil. Auch Teile eines "
                                                          "Notfall-Pakets gehen – dann wird nur die "
                                                          "Identitäts-Schlüsseldatei wiederhergestellt."), fill="both", expand=True)
        fr, self.t_shares = scrolled_text(c, height=8, font=(MONO, 11), app=self)
        fr.pack(fill="both", expand=True)
        r = row(c)
        ttk.Button(r, text=_("Teil-Dateien öffnen…"), command=self.load_shares).pack(side="left")
        ttk.Button(r, text=_("Wiederherstellen und speichern…"), style="Primary.TButton",
                   command=self.combine_shares).pack(side="right")

    def split_keyfile(self, kf=None, on_done=None):
        if kf is None:
            src = filedialog.askopenfilename(title=_("Schlüsseldatei für das Backup"),
                                             filetypes=[(_("Schlüsseldatei"), "*.sakey")])
            if not src:
                return False
            try:
                kf = read_keyfile_path(src, _("das Backup"))
            except core.SigillumError as e:
                messagebox.showerror("Sigillum Arcanum", str(e))
                return False
        tag = secrets.token_hex(3).upper()
        parts = shamir.split(kf, 3, 2)
        ok = self._hand_out_parts(parts, tag, _("Backup"), lambda p, t, i, n, k, _tag: pdfout.share_sheet(p, t, i, n, k),
                                  _("Passphrase und PIN"))
        if ok:
            self.cfg.note("backup_kf", core.keyfile_digest(kf))
            self.refresh_start()
            messagebox.showinfo(_("Backup erzeugt"), _("Backup {0}: 3 Teile, 2 genügen zur Wiederherstellung.").format(tag))
        if on_done:
            on_done(ok)
        return ok

    def load_shares(self):
        texts = []
        for p in filedialog.askopenfilenames(filetypes=[(_("Backup-Teil"), "*.sashare")]):
            try:
                texts.append(self.share_to_text(read_file(p, 1024)))
            except (OSError, core.SigillumError):
                return messagebox.showerror("Sigillum Arcanum", _("Nicht lesbar: {0}").format(p))
        if texts:
            set_text(self.t_shares, "\n\n".join(texts))

    def combine_shares(self):
        blocks = [b for b in re.split(r"\n[ \t]*\n", get_text(self.t_shares).strip()) if b.strip()]
        try:
            parts = [bytes.fromhex("".join(b.split())) for b in blocks]
            suspect = []
            if parts and shamir.kind(parts) == shamir.PACKAGE_MAGIC:
                kf = notfall.open_parts(parts)[0]          # Notfall-Paket: nur die Schlüsseldatei herausgeben
            else:
                kf, suspect = shamir.combine_keyfile(parts)   # Befund R8-H4: alle Paare prüfen
            core.read_keyfile(kf)
        except (ValueError, core.SigillumError) as e:
            return messagebox.showerror(_("Wiederherstellung fehlgeschlagen"), str(e))
        if suspect:
            names = []
            for i in suspect:
                try:
                    names.append(str(shamir.parse(parts[i])["x"]))
                except ValueError:
                    names.append(_("(Eingabe {0}, unlesbar)").format(i + 1))
            messagebox.showwarning(
                _("Verdächtiger Backup-Teil"),
                _("Teil ") + ", ".join(names) + _(" passt nicht zu den übrigen Teilen (falsch abgetippt oder "
                                               "verfälscht). Die Schlüsseldatei wurde aus den stimmigen Teilen "
                                               "wiederhergestellt. Prüfe, wer Zugang zu diesem Teil hatte, und "
                                               "erzeuge danach ein neues Backup."))
        p = filedialog.asksaveasfilename(defaultextension=".sakey", filetypes=[(_("Schlüsseldatei"), "*.sakey")])
        if p:
            try:
                write_new(p, kf)
            except FileExistsError:
                return messagebox.showerror("Sigillum Arcanum", _("Datei existiert bereits – wird nicht "
                                                                  "überschrieben."))
            set_text(self.t_shares, "")
            messagebox.showinfo(_("Wiederhergestellt"), _("Schlüsseldatei erfolgreich wiederhergestellt."))

    # ================================================= Hand-Modus
    def page_hand(self, f):
        page_title(f, _("Hand-Modus"), _("Einmalblock mit Fälschungsschutz – von Hand rechenbar, beweisbar sicher. "
                                      "Jedes Blatt genau einmal, nur lokal drucken, danach vernichten."))
        c = card(f, _("Druckvorlagen"))
        r = row(c)
        ttk.Label(r, text=_("Blöcke à 10 Zeichen:"), style="Card.TLabel").pack(side="left")
        self.v_blocks = tk.IntVar(value=10)
        ttk.Spinbox(r, from_=2, to=handmode.MAX_BLOCKS, increment=2, textvariable=self.v_blocks, width=5).pack(
            side="left", padx=6)
        ttk.Button(r, text=_("Zufallsblatt erzeugen (PDF, 2 Exemplare)…"), style="Primary.TButton",
                   command=self.make_pad).pack(side="left", padx=6)
        ttk.Button(r, text=_("Referenzkarte + Tafeln (PDF)…"), command=self.make_card).pack(side="left")
        ttk.Label(c, text=_("Vier Prüfwerte schützen gegen Fälschung (1 : 1.048.576)."), style="Muted.TLabel").pack(
            anchor="w")

        c = card(f, _("Rechenhilfe"), _("Optional – von Hand geht es mit Referenzkarte und Tafeln. Das Register "
                                     "benutzter Blätter liegt verschlüsselt in deiner Identität."), fill="both", expand=True)
        r = row(c)
        ttk.Label(r, text=_("Blatt-Nr."), style="Card.TLabel").pack(side="left")
        self.v_sheet = tk.StringVar()
        ttk.Entry(r, textvariable=self.v_sheet, width=22, font=(MONO, 10)).pack(side="left", padx=6)
        ttk.Label(r, text=_("Blattcode (letzte Seite des Blatts):"), style="Card.TLabel").pack(side="left", padx=(12, 4))
        fr, self.t_pad = scrolled_text(c, height=3, font=(MONO, 10), app=self)
        fr.pack(fill="x")
        ttk.Label(c, text=_("Klartext"), style="Card.TLabel").pack(anchor="w", pady=(6, 0))
        fr, self.t_hplain = scrolled_text(c, height=3, font=(FONT, 11), app=self)
        fr.pack(fill="x")
        r = row(c)
        ttk.Button(r, text=_("↓ Verschlüsseln"), style="Primary.TButton", command=self.hand_encrypt).pack(side="left")
        ttk.Button(r, text=_("↑ Entschlüsseln"), command=self.hand_decrypt).pack(side="left", padx=8)
        self.l_hand = ttk.Label(r, text="", style="Muted.TLabel", wraplength=560, justify="left")
        self.l_hand.pack(side="left", padx=8)
        ttk.Label(c, text=_("Geheimtext (Glyphen)"), style="Card.TLabel").pack(anchor="w")
        fr, self.t_hcipher = scrolled_text(c, height=4, font=self.glyph_font, app=self)
        fr.pack(fill="both", expand=True)

    def _hand_label(self, text, warn=False):
        self.l_hand.configure(text=text, style="Warn.TLabel" if warn else "Muted.TLabel")
        self.set_status(text)                    # Statuszeile nicht auf „Verschlüssele …“ stehen lassen

    def make_pad(self):
        try:
            sheet = handmode.Sheet.new(int(self.v_blocks.get()))
        except (handmode.HandError, ValueError, tk.TclError) as e:
            return messagebox.showerror(_("Hand-Modus"), str(e))
        printed = self.print_only(_("Zufallsblatt {0}").format(sheet.id), f"{_('zufallsblatt')}_{sheet.id}.pdf",
                                  lambda p: pdfout.pad_sheets(p, sheet))
        if printed:
            messagebox.showinfo(_("Zufallsblatt"), _("Blatt Nr. {0}: Die App speichert die Werte nicht; die "
                                                  "PDF-Datei wurde gelöscht.\n\n2 Exemplare: eines für dich, "
                                                  "eines persönlich übergeben. Das Blatt genau einmal verwenden, "
                                                  "danach vernichten.").format(sheet.id))

    def make_card(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="referenzkarte.pdf",
                                         filetypes=[("PDF", "*.pdf")])
        if p:
            pdfout.reference_card(p)
            self.set_status(_("Referenzkarte gespeichert: {0}").format(p))

    def _sheet(self):
        return handmode.Sheet.from_code(self.v_sheet.get(), get_text(self.t_pad))

    def hand_encrypt(self):
        try:
            self.require_vault()            # Register benutzter Blätter liegt verschlüsselt in der Identität (L7)
            sheet = self._sheet()
            text = get_text(self.t_hplain)
            if self.vault.sheet_used(sheet.id):
                raise handmode.HandError(_("Blatt {0} wurde bereits verwendet. Ein zweites Mal würde die "
                                           "Verschlüsselung knackbar machen – abgelehnt. Neues Blatt nehmen.").format(sheet.id))
            handmode.encrypt(text, sheet)   # Vorabprüfung (Länge, Zeichen)
        except ERRORS as e:
            return messagebox.showerror(_("Hand-Modus"), str(e))

        def action(v):
            if v.sheet_used(sheet.id):                 # erneut prüfen: Stand zum Zeitpunkt des Speicherns
                raise handmode.HandError(_("Blatt {0} wurde bereits verwendet – abgelehnt.").format(sheet.id))
            c = handmode.encrypt(text, sheet)
            v.mark_sheet(sheet.id, handmode.message_digest(c))
            return c

        def done(c):
            n = len(c) - handmode.TAGS
            set_text(self.t_hcipher, codec.values_to_glyphs(c[:n], line=99) + "   "
                     + codec.values_to_glyphs(c[n:], line=99))
            set_text(self.t_pad, "")
            self._hand_label(_("{0} Zeichen (davon 4 Prüfwerte) · Blatt {1} als benutzt gespeichert").format(len(c), sheet.id))
        self.vault_op(_("Verschlüssele"), action, done)

    def hand_decrypt(self):
        """Befund R2-1: Auch der Empfänger vermerkt das Blatt, damit es nicht für die Antwort wiederverwendet wird.
        Der Klartext erscheint erst, nachdem das Register gespeichert ist."""
        set_text(self.t_hplain, "")
        try:
            self.require_vault()
            sheet = self._sheet()
            cipher = codec.text_to_values(get_text(self.t_hcipher))
            text = handmode.decrypt(cipher, sheet)
        except ERRORS as e:
            return messagebox.showerror(_("Hand-Modus"), str(e))
        msg = handmode.message_digest(cipher)
        box = {}

        def action(v):
            box["before"], box["opened"] = v.sheet_message(sheet.id), v.sheet_opened(sheet.id)
            v.mark_sheet(sheet.id, msg)
            if box["before"] is None or box["before"] == msg:
                v.mark_opened(sheet.id)

        def done(_u):
            before = box["before"]
            set_text(self.t_pad, "")
            set_text(self.t_hplain, text)
            if before == msg and box["opened"]:          # Befund R3-2
                self._hand_label(_("ACHTUNG: bereits entschlüsselt (Blatt {0})").format(sheet.id), warn=True)
                messagebox.showwarning(
                    _("Bereits entschlüsselt"),
                    _("Diese Nachricht wurde mit Blatt {0} bereits entschlüsselt ({1}×).\n\nWurde sie dir "
                      "wirklich gerade neu zugestellt, kann es eine Wiederholung durch Dritte sein (z. B. ein "
                      "alter Treffpunkt). Inhalt und Echtheit sind unverändert – prüfe aber, ob die Nachricht "
                      "noch aktuell ist.").format(sheet.id, box['opened']))
                return
            if before is None or before == msg:
                own = _(" · deine eigene Nachricht") if before == msg else ""
                self._hand_label(_("Prüfwerte in Ordnung – echt und unverändert · Blatt {0} als benutzt "
                                   "gespeichert{1}").format(sheet.id, own))
                return
            self._hand_label(_("ACHTUNG: Blatt {0} wurde mehrfach verwendet").format(sheet.id), warn=True)
            messagebox.showwarning(
                _("Blatt mehrfach verwendet"),
                _("Blatt {0} wurde schon für eine ANDERE Nachricht benutzt").format(sheet.id)
                + (_(" (in einer älteren Version vermerkt)") if before == "" else "") + _(".\n\nZwei Nachrichten "
                                                                                        "mit demselben Blatt kann "
                                                                                        "ein Angreifer "
                                                                                        "gegeneinander rechnen "
                                                                                        "und lesen. Behandle "
                                                                                        "beide Nachrichten als "
                                                                                        "NICHT geheim, vernichte "
                                                                                        "das Blatt und sprich mit "
                                                                                        "deinem Partner ab, dass "
                                                                                        "jedes Blatt nur für EINE "
                                                                                        "Nachricht in EINE "
                                                                                        "Richtung verwendet wird."))
        self.vault_op(_("Vermerke Blatt"), action, done)
