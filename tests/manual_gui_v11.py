"""Oberflächentest Version 11 (öffnet ein Fenster): Assistent, Alltag ohne Passphrase, automatische Sperre,
Schnell-Entsperren, Partner, Cloud-/Ordner-Warnungen, Schritt-Bestätigung, Design. Aufruf: python tests/manual_gui_v11.py"""
import glob, os, sys, tempfile, time, hashlib
tmp = tempfile.mkdtemp()
os.environ['SIGILLUM_LANG'] = 'de'  # prüft deutsche Meldungstexte
os.environ['APPDATA'] = tmp; os.environ['LOCALAPPDATA'] = tmp; os.environ['SIGILLUM_NO_WIZARD'] = '1'
for v in ('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial'):
    os.environ.pop(v, None)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); sys.path.insert(0, HERE)
from tkinter import messagebox, filedialog
LOG = []; ANS = [True]; DIRQ = []
for n in ('showinfo', 'showerror', 'showwarning'):
    setattr(messagebox, n, lambda *a, _n=n, **k: LOG.append((_n, str(a[1]) if len(a) > 1 else '')))
messagebox.askyesno = lambda *a, **k: ANS[0]
messagebox.askokcancel = lambda *a, **k: True
filedialog.askdirectory = lambda *a, **k: DIRQ.pop(0) if DIRQ else ''
from sigillum import gui, core, ratchet, codec, gui_wizard, gui_base, gui_pages
from softtoken import SoftToken
core.KDF_OPS, core.KDF_MEMLOG, core.ALLOWED_KDF = 1, 26, {(1, 26)}
TOK = SoftToken(); gui.fidokey.Fido2Token = lambda ui=None: TOK
app = gui.App()
FACT = {}
app.ask_factors = lambda *a, **k: FACT.get('v')
res = {}


def wait(n=1):
    for _ in range(n):
        for _ in range(3000):
            app.update(); time.sleep(0.01)
            if not app.busy:
                for _ in range(5): app.update(); time.sleep(0.01)
                if not app.busy: break
        else:
            raise SystemExit('timeout')


def last(kind=None):
    l = [x for x in LOG if kind is None or x[0] == kind]; return l[-1][1] if l else ''


def mk(*p):
    d = os.path.join(tmp, *p); os.makedirs(d, exist_ok=True); return d


def pkg(name):
    pr = mk(name, 'druck'); ds = [mk(name, f'teil{i}') for i in (1, 2, 3)]
    DIRQ[:] = [pr] + ds
    return pr, ds


# ------------------------------------------------------------------ Einrichtungs-Assistent komplett
iddir, kfdir = mk('lokal', 'ident'), mk('usbstick')
w = gui_wizard.SetupWizard(app); app.update()
w.next()                                                         # Willkommen
w.s['id_dir'].set(iddir); w.s['kf_dir'].set(iddir); LOG.clear(); w.next()
res['W1 gleicher Ordner für Identität und Schlüsseldatei abgelehnt'] = w.i == 1 and 'NICHT im selben' in last('showerror')
w.s['kf_dir'].set(kfdir); w.next()
w.s['name'].set('Carl'); w.next()
kfp = os.path.join(kfdir, 'Carl_identitaet.sakey')
res['W2 Schlüsseldatei direkt im USB-Ordner erzeugt'] = os.path.exists(kfp) and w.i == 3
pw = w.s['pw']; w.v_written.set(True); w.v_retype.set('falsch'); LOG.clear(); w.next()
res['W3 falsche Abschrift der Passphrase abgelehnt'] = w.i == 3 and 'Abschrift' in last('showerror')
w.v_retype.set(pw.upper()); w.next()
w.v_pin1.set('12345'); w.v_pin2.set('12345'); LOG.clear(); w.next()
res['W4 PIN unter 6 Zeichen abgelehnt'] = w.i == 4 and '6' in last('showerror')
w.v_pin1.set('864209'); w.v_pin2.set('864209'); w.next()
w.next(); wait()                                                 # Identität erzeugen
idp = os.path.join(iddir, 'Carl.said')
res['W5 Identität erzeugt und entsperrt'] = os.path.exists(idp) and app.vault and app.vault.identity.name == 'Carl' and w.i == 6
pr, ds = pkg('bk'); w._backup(); wait()
res['W6 Backup gedruckt, Teile getrennt, PDFs gelöscht'] = w.s['backup'] and os.listdir(pr) == [] and all(len(os.listdir(d)) == 1 for d in ds)
w.next()
pr, ds = pkg('nf'); w._fido(); wait(3)
res['W7 YubiKey im Assistenten ohne erneute Passphrase-Abfrage'] = app.vault.fido and ratchet.file_mode(open(idp, 'rb').read()) == 5
w.next(); w.next()
res['W8 Assistent beendet, Geheimnisse aus dem Assistenten entfernt'] = not w.winfo_exists() and w.s['pw'] is None and w.s['kf'] is None
res['W9 Pfade gemerkt, keine Geheimnisse in den Einstellungen'] = (app.cfg.d['last_id'] == idp and app.cfg.d['last_ikf'] == kfp
                                                                   and pw.split()[0] not in open(app.cfg.path).read())

# ------------------------------------------------------------------ Alltag: Entsperren ohne Passphrase
app.lock(); app.v_id.set(idp); app.v_ikf.set(kfp); app.v_ipass.set(''); app.v_ipin.set('864209'); app.unlock(); wait()
res['A1 Alltag mit YubiKey ohne Passphrase'] = app.vault is not None and app.vault.fido and app.vault._key is None
res['A2 Passphrase-Feld bei YubiKey-Identität ausgeblendet'] = not app._pw_row[1].winfo_ismapped()
app.lock(); app.v_ipin.set('000000'); LOG.clear(); app.unlock(); wait()
res['A3 falsche App-PIN im Alltag abgelehnt'] = app.vault is None and 'passen nicht' in last('showerror')

# ------------------------------------------------------------------ Schritt-Bestätigung (Passphrase für Änderungen)
app.v_ipin.set('864209'); app.unlock(); wait()
before = open(idp, 'rb').read(); FACT['v'] = ('falsche worte hier und da noch', '864209'); LOG.clear(); pkg('nf2'); app.fido_renew(); wait()
res['S1 Notfall-Paket erneuern mit falscher Passphrase abgelehnt, nichts geändert'] = open(idp, 'rb').read() == before and 'passen nicht' in last('showerror')
FACT['v'] = None; LOG.clear(); app.fido_renew(); wait()
res['S2 Abbruch der Schritt-Bestätigung ändert nichts'] = open(idp, 'rb').read() == before
FACT['v'] = (pw, '864209'); pr, ds = pkg('nf3'); app.fido_renew(); wait(2)
res['S3 Erneuern mit richtiger Passphrase in Alltags-Sitzung'] = open(idp, 'rb').read() != before and app.vault.fido

# ------------------------------------------------------------------ automatische Sperre
gui.set_text(app.t_plain, 'geheimer Klartext'); app.v_pass.set('x y z'); app._last_act = time.monotonic() - 10 ** 6
app._idle_tick(); app.update()
res['L1 automatische Sperre nach Zeit, Felder geleert'] = app.vault is None and gui.get_text(app.t_plain) == '' and app.v_pass.get() == ''
res['L2 ohne Schnell-Entsperren keine versiegelte Sitzung'] = app._sealed is None

# ------------------------------------------------------------------ Schnell-Entsperren
app.v_quick.set(True); app._quick_changed()
app.v_ipin.set('864209'); app.unlock(); wait()
app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update()
res['Q1 versiegelte Sitzung nach automatischer Sperre'] = app.vault is None and app._sealed is not None and app.f_quick.winfo_ismapped()
app.v_qpin.set('111111'); app.quick_unlock(); wait()
app.v_qpin.set('864209'); app.quick_unlock(); wait(2)
res['Q2 falsche PIN, dann richtige: fortgesetzt'] = app.vault is not None and app.vault.identity.name == 'Carl'
app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update()
for _ in range(3):
    app.v_qpin.set('111111'); app.quick_unlock(); wait()
res['Q3 nach 3 falschen PINs verworfen'] = app._sealed is None and app.vault is None
app.v_ipin.set('864209'); app.unlock(); wait(2)
app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update()
open(idp, 'ab').write(b'')                                       # unverändert lassen ...
b = open(idp, 'rb').read(); open(idp, 'wb').write(b[:-1] + bytes([b[-1] ^ 1]))   # ... dann von außen verändern
app.v_qpin.set('864209'); LOG.clear(); app.quick_unlock(); wait()
res['Q4 Datei von außen geändert: Schnell-Entsperren abgelehnt'] = app.vault is None and app._sealed is None and 'geändert' in last('showerror')
open(idp, 'wb').write(b)
app.v_ipin.set('864209'); app.unlock(); wait(2)
app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update(); app.lock('manuell')
res['Q5 manuelles Sperren verwirft die versiegelte Sitzung'] = app._sealed is None

# ------------------------------------------------------------------ Befunde der Prüfrunde 9 (R11)
def idle_lock():
    app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update()
app.v_ipin.set('864209'); app.unlock(); wait(2); idle_lock()
b = open(idp, 'rb').read(); open(idp, 'wb').write(b[:-1] + bytes([b[-1] ^ 1]))
app.v_qpin.set('000000'); LOG.clear(); app.quick_unlock(); wait()
res['R11-Ha falsche PIN + geänderte Datei: dieselbe Meldung wie bei richtiger PIN'] = app._sealed is None and 'geändert' in last('showerror')
open(idp, 'wb').write(b)
app.v_ipin.set('864209'); app.unlock(); wait(2); idle_lock()
app.busy = True; app.v_qpin.set('000000'); app.quick_unlock(); app.quick_unlock(); app.busy = False
res['R11-M5 Klick während laufender Prüfung zählt keinen Versuch'] = app._sealed is not None and app._sealed['tries'] == 0
app.v_qpin.set(''); LOG.clear(); app.quick_unlock()
res['R11-M5b leere PIN zählt keinen Versuch'] = app._sealed['tries'] == 0 and 'PIN' in last('showerror')
app.v_qpin.set('864209'); app.quick_unlock(); wait(2)
app._recovery_secret = ('x', 'y'); idle_lock()
res['R11-M2 nach Notfall-Entsperren keine versiegelte Sitzung'] = app.vault is None and app._sealed is None
app.v_ipin.set('864209'); app.unlock(); wait(2)
gui.set_text(app.t_plain, 'GEHEIM'); app.lock('manuell')
res['R11-M4 manuelles Sperren leert den Klartext'] = gui.get_text(app.t_plain) == ''
app.v_ipin.set('864209'); app.unlock(); wait(2)
pwz = gui_wizard.PartnerWizard(app); app.update(); pwz.next(); pwz.s['name'].set('Zed'); pwz.next()
had = pwz.s['pw'] is not None
idle_lock()
res['R11-M3 automatische Sperre schließt den Partner-Assistenten und leert ihn'] = had and not pwz.winfo_exists() and pwz.s['pw'] is None
app.v_quick.set(False); app._quick_changed()

# ------------------------------------------------------------------ Kopfzeile: Knopf wechselt mit dem Zustand
app.update()
res['K1 gesperrt: oben "Entsperren"'] = app.vault is None and app.b_lock.cget('text') == 'Entsperren' and str(app.b_lock.cget('style')) == 'Primary.TButton'
app.show('write'); app.b_lock.invoke(); app.update(); app.update()
res['K2 Klick führt zur Startseite, Cursor im PIN-Feld'] = app.current == 'start' and app.focus_get() is app.e_ipin
app.v_ipin.set('864209'); app.unlock(); wait(2)
res['K3 entsperrt: oben "Jetzt sperren"'] = app.b_lock.cget('text') == 'Jetzt sperren' and str(app.b_lock.cget('style')) == 'Danger.TButton'
app.b_lock.invoke(); app.update()
res['K4 Klick sperrt'] = app.vault is None and app.b_lock.cget('text') == 'Entsperren'
app.v_quick.set(True); app._quick_changed()
app.v_ipin.set('864209'); app.unlock(); wait(2); app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update()
res['K5 versiegelt: oben "Mit PIN fortsetzen", Klick setzt Cursor ins PIN-Feld'] = (app.b_lock.cget('text') == 'Mit PIN fortsetzen'
    and (app.b_lock.invoke() or True) and (app.update() or True) and app.focus_get() is app.e_qpin)
app.lock('manuell'); app.v_quick.set(False); app._quick_changed()
# Modus-Hinweis folgt der Datei (YubiKey-Identität: Passphrase-Feld ausgeblendet, auch ohne neue Pfadeingabe)
app.refresh_start(); app.update()
res['K6 Passphrase-Feld folgt dem Dateimodus bei jedem Auffrischen'] = (ratchet.file_mode(open(idp, 'rb').read(16)) == 5) == (not app._pw_row[1].winfo_ismapped())

# ------------------------------------------------------------------ Partner (Variante C)
app.v_ipin.set('864209'); app.unlock(); wait(2)
pw_ = gui_wizard.PartnerWizard(app); app.update()
pw_.next(); pw_.s['name'].set('Dora'); pw_.next()
pkf, ppw, ppin = pw_.s['kf'], pw_.s['pw'], pw_.s['pin']
pw_.next()
stick = mk('stick_dora'); DIRQ[:] = [stick]; pw_._save_stick(); pw_.next()
prs = mk('druck_dora'); DIRQ[:] = [prs]; pw_._print(); pw_.next()
res['P1 Schlüsseldatei für Partner gespeichert, Übergabeblatt gedruckt und gelöscht'] = os.listdir(stick) == ['gemeinsam_Dora.sakey'] and os.listdir(prs) == []
pw_.next(); wait()
res['P2 Partner in der Identität gespeichert (mit YubiKey vorgeschlagen)'] = [p[1] for p in app.vault.partners()] == ['Dora'] and not pw_.winfo_exists()
blob = open(idp, 'rb').read()
res['P3 Partner-Geheimnisse nicht im Klartext der Datei'] = pkf not in blob and ppw.split()[0].encode() not in blob
app.v_mode.set('partner'); app.refresh_partners(); app.cb_partner.current(0)
gui.set_text(app.t_plain, 'Hallo Dora'); app.do_encrypt(); wait()
ct = gui.get_text(app.t_cipher)
res['P4 Verschlüsseln mit Partner'] = ct != '' and core.decrypt_shared(codec.decode(ct), ppw, ppin, pkf)['text'] == 'Hallo Dora'
gui.set_text(app.t_in, ct); app.cb_rshared.current(1); app._rshared_changed(); app.do_decrypt(); wait()
res['P5 Lesen mit gespeichertem Partner'] = 'Hallo Dora' in gui.get_text(app.t_out)
app.cb_rshared.current(0); app._rshared_changed(); app.v_pass.set(ppw); app.v_pin.set(ppin)
app.v_kf.set(os.path.join(stick, 'gemeinsam_Dora.sakey')); app.do_decrypt(); wait()
res['P6 Lesen von Hand mit denselben Faktoren'] = 'Hallo Dora' in gui.get_text(app.t_out)
# Übernehmen eines vorhandenen Schlüssels, lose Kopie wird angeboten zu löschen
copyp = os.path.join(mk('lose'), 'kopie.sakey'); open(copyp, 'wb').write(core.new_keyfile())
class FakeDlg:
    def __init__(self, a): self.result = ('Emil', copyp, core.generate_passphrase(7), '246802')
gui_wizard.PartnerImportDialog = FakeDlg; app.wait_window = lambda d: None
ANS[0] = True; app.partner_import(); wait()
res['P7 vorhandenen Schlüssel übernommen, lose Kopie gelöscht'] = 'Emil' in [p[1] for p in app.vault.partners()] and not os.path.exists(copyp)
class SameKF:
    def __init__(self, a): self.result = ('Fritz', kfp, core.generate_passphrase(7), '246802')
gui_wizard.PartnerImportDialog = SameKF; LOG.clear(); app.partner_import(); wait()
res['P8 H1: Identitäts-Schlüsseldatei als Partner abgelehnt'] = 'Identität' in last('showerror') and 'Fritz' not in [p[1] for p in app.vault.partners()]
del app.wait_window

# ------------------------------------------------------------------ Warnungen Cloud / gleicher Ordner
cl = mk('OneDrive', 'Sigillum'); ckf = os.path.join(cl, 'carl.sakey'); open(ckf, 'wb').write(open(kfp, 'rb').read())
app.lock(); app.v_ikf.set(ckf); app.v_ipin.set('864209'); LOG.clear(); app.unlock(); wait()
res['C1 Warnung: Schlüsseldatei im Cloud-Ordner'] = any(k == 'showwarning' and 'Cloud' in t for k, t in LOG)
same = os.path.join(iddir, 'carl_gleich.sakey'); open(same, 'wb').write(open(kfp, 'rb').read())
app.lock(); app.v_ikf.set(same); app.v_ipin.set('864209'); LOG.clear(); app.unlock(); wait()
res['C2 Warnung: Schlüsseldatei im selben Ordner wie die Identität'] = any('SELBEN Ordner' in t for k, t in LOG)
app.refresh_start()
res['C3 Startseite nennt die Warnungen'] = 'selben Ordner' in app.l_state.cget('text')

# ------------------------------------------------------------------ R12-N4: zurückgespielte ältere Fassung
app.lock(); app.v_ikf.set(kfp); app.v_ipin.set('864209'); app.unlock(); wait(2)
old_blob = open(idp, 'rb').read()
app.vault_op('Test', lambda v: None, lambda _: None); wait()
new_blob = open(idp, 'rb').read()
app.lock(); open(idp, 'wb').write(old_blob)
ANS[0] = False; app.v_ipin.set('864209'); app.unlock(); wait(2)
res['R12-N4a ältere Fassung erkannt, ohne Zustimmung nicht geöffnet'] = app.vault is None and 'ältere Fassung' in app.status.cget('text')
ANS[0] = True; app.v_ipin.set('864209'); app.unlock(); wait(2)
res['R12-N4b mit Zustimmung geöffnet (bewusstes Backup)'] = app.vault is not None
app.lock(); open(idp, 'wb').write(new_blob)
app.v_ipin.set('864209'); app.unlock(); wait(2)
res['R12-N4c neuere Fassung öffnet ohne Rückfrage'] = app.vault is not None

# ------------------------------------------------------------------ R12-H2: Zwischenablage beim Sperren
app.v_ipin.set('864209'); app.unlock(); wait(2)
gui.set_text(app.t_out, 'Treffen um 14:30 GEHEIMER KLARTEXT'); app.clipboard_clear(); app.clipboard_append('GEHEIMER KLARTEXT')
app.lock('manuell'); app.update()
try:
    clip = app.clipboard_get()
except Exception:
    clip = ''
res['R12-H2a Klartext in der Zwischenablage wird beim Sperren geleert'] = clip == ''
app.v_ipin.set('864209'); app.unlock(); wait(2)
gui.set_text(app.t_out, 'GEHEIMER KLARTEXT'); app.clipboard_clear(); app.clipboard_append('ᚠᚢᚦ Geheimtext')
app.lock('manuell'); app.update()
res['R12-H2b Geheimtext in der Zwischenablage bleibt'] = app.clipboard_get() == 'ᚠᚢᚦ Geheimtext'

app.v_ipin.set('864209'); app.unlock(); wait(2)
app.note_plaintext('Zeile eins\nGEHEIME ZEILE ZWEI'); gui.set_text(app.t_out, ''); app.clipboard_clear(); app.clipboard_append('GEHEIME ZEILE ZWEI')
app.lock('manuell'); app.update()
try:
    clip = app.clipboard_get()
except Exception:
    clip = ''
res['R14-H2 früherer Klartext (Feld schon leer) wird beim Sperren aus der Zwischenablage entfernt'] = clip == ''

# ------------------------------------------------------------------ Code-Scanning #6: Teil einer Zeile kopiert
app.v_ipin.set('864209'); app.unlock(); wait(2)
app.show('write'); gui.set_text(app.t_plain, 'Treffpunkt morgen 7 Uhr am Nordtor'); app.update()
app.t_plain.tag_add('sel', '1.10', '1.20'); app.t_plain.focus_force(); app.t_plain.event_generate('<<Copy>>'); app.update()
copied = app.clipboard_get()
gui.set_text(app.t_plain, ''); app.lock('manuell'); app.update()
try:
    clip = app.clipboard_get()
except Exception:
    clip = ''
res['CS6 kopierter Ausschnitt (Feld danach geleert) wird beim Sperren entfernt'] = copied.strip() == 'morgen 7' and clip == ''

# ------------------------------------------------------------------ Code-Scanning #4: Sperren während eines Vorgangs
app.v_ipin.set('864209'); app.unlock(); wait(2)
got = {}
app.run('Test', lambda: (lambda: time.sleep(1.5) or 'KLARTEXT'), lambda r: got.update(r=r))
app.update(); busy_before = app.busy
app.lock('manuell'); app.update()
locked_while_busy = app.vault is None
for _ in range(300):
    app.update(); time.sleep(0.01)
    if not app.busy: break
for _ in range(10): app.update(); time.sleep(0.01)
res['CS4a Sperren während eines Vorgangs, Ergebnis verworfen'] = busy_before and locked_while_busy and 'r' not in got and not app.busy
app.v_ipin.set('864209'); app.unlock(); wait(2)
app.run('Test', lambda: (lambda: time.sleep(1.5) or 'x'), lambda r: got.update(r2=r)); app.update()
app._last_act = time.monotonic() - 10 ** 6; app._idle_tick(); app.update()
locked_auto = app.vault is None
for _ in range(300):
    app.update(); time.sleep(0.01)
    if not app.busy: break
res['CS4b automatische Sperre greift auch während eines Vorgangs'] = locked_auto and 'r2' not in got
app.v_ipin.set('864209'); app.unlock(); wait(2)
skf = core.new_keyfile(); spw = core.generate_passphrase(); blob = core.encrypt_shared('x', spw, '135790', skf, b'\0' * 16)
gui.set_text(app.t_in, '\n\n'.join([codec.encode(blob, True)] * (gui_pages.MAX_SHARED_BATCH + 1)))
app.cb_rshared.current(0); LOG.clear()
kfpath = os.path.join(tmp, 'skf.sakey'); open(kfpath, 'wb').write(skf)
app.v_kf.set(kfpath); app.v_pass.set(spw); app.v_pin.set('135790')
app.confirm_foreign_pw = lambda pw: True
app.show('read'); app.do_decrypt(); wait(3)
out = gui.get_text(app.t_out)
res['CS4c höchstens 10 gemeinsame Nachrichten je Lauf'] = 'höchstens 10' in out and out.count('echt und unverändert') == 10

# ------------------------------------------------------------------ Design
th0 = app.cfg.ui('theme'); app.toggle_theme(); app.update()
res['D1 Design umschaltbar und gespeichert'] = app.cfg.ui('theme') != th0 and app.t_plain.cget('background') == gui_base.PALETTES[app.cfg.ui('theme')]['input']
app.toggle_theme()
res['D2 Navigation zeigt aktive Seite'] = (app.show('read') or True) and str(app.nav['read'].cget('style')) == 'NavActive.TButton'

app.on_close()
wd = max(len(k) for k in res)
for k, v in res.items():
    print(f"{k:<{wd}}  {'OK' if v else 'FEHLER'}")
print('alle bestanden' if all(res.values()) else 'FEHLER VORHANDEN')
sys.exit(0 if all(res.values()) else 1)
