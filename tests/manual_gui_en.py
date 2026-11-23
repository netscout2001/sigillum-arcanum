"""Oberflächentest Englisch (öffnet ein Fenster): Assistent, Entsperren, alle Seiten, Partner-Assistent, Meldungen –
überall wird nach deutschen Resten gesucht. Aufruf: python tests/manual_gui_en.py

English UI test: walks the wizard, unlocks, visits every page and dialog and reports any leftover German text."""
import os, re, sys, tempfile, time
tmp = tempfile.mkdtemp()
os.environ['APPDATA'] = tmp; os.environ['LOCALAPPDATA'] = tmp; os.environ['SIGILLUM_NO_WIZARD'] = '1'
os.environ['SIGILLUM_LANG'] = 'en'
for v in ('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial'):
    os.environ.pop(v, None)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); sys.path.insert(0, HERE)
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
LOG = []; DIRQ = []
for n in ('showinfo', 'showerror', 'showwarning', 'askyesno', 'askokcancel'):
    setattr(messagebox, n, lambda *a, _n=n, **k: LOG.append((_n, ' | '.join(str(x) for x in a))) or
            (True if _n.startswith('ask') else None))
filedialog.askdirectory = lambda *a, **k: (LOG.append(('dir', k.get('title', ''))), DIRQ.pop(0) if DIRQ else '')[1]
from sigillum import gui, core, ratchet, gui_wizard, i18n
from softtoken import SoftToken
assert i18n.LANG == 'en'
core.KDF_OPS, core.KDF_MEMLOG, core.ALLOWED_KDF = 1, 26, {(1, 26)}
TOK = SoftToken(); gui.fidokey.Fido2Token = lambda ui=None: TOK
app = gui.App()
FACT = {}
app.ask_factors = lambda *a, **k: FACT.get('v')

import json
_CAT = json.load(open(os.path.join(os.path.dirname(HERE), 'sigillum', 'locale', 'en.json'), encoding='utf-8'))
_WORD = re.compile(r"[A-Za-zÄÖÜäöüß]{4,}")
_EN_WORDS = {w.lower() for v in _CAT.values() for w in _WORD.findall(v)}
# Wörter, die nur in den deutschen Texten vorkommen – findet sich eines in der Oberfläche, ist es ein deutscher Rest
DE_WORDS = {w.lower() for k in _CAT for w in _WORD.findall(k)} - _EN_WORDS
GERMAN = re.compile(r"[äöüÄÖÜß]|\b(" + "|".join(sorted(map(re.escape, DE_WORDS), key=len, reverse=True)) + r")\b",
                    re.IGNORECASE)
ALLOWED = ("Sprache / Language", "Deutsch", "Gilt ab dem nächsten Start. / Takes effect after a restart.",
           "ä=ae, ö=oe, ü=ue, ß=ss", "installieren.bat")
found = {}


def check(where, text):
    for a in ALLOWED:
        text = text.replace(a, "")
    if GERMAN.search(text):
        found.setdefault(text.strip()[:160], where)


def scan(where, w):
    try:
        if isinstance(w, (tk.Tk, tk.Toplevel)):
            check(where + ' title', w.title())
        for opt in ('text',):
            try:
                check(where, str(w.cget(opt)))
            except tk.TclError:
                pass
        if isinstance(w, ttk.Combobox):
            for v in w.cget('values'):
                check(where + ' combo', str(v))
        if isinstance(w, ttk.Treeview):
            for c in w.cget('columns'):
                check(where + ' heading', w.heading(c, 'text'))
        if isinstance(w, tk.Text):
            check(where + ' textfield', w.get('1.0', 'end'))
        for ch in w.winfo_children():
            scan(where, ch)
    except tk.TclError:
        pass


def wait(n=1):
    for _ in range(n):
        for _ in range(3000):
            app.update(); time.sleep(0.01)
            if not app.busy:
                for _ in range(5): app.update(); time.sleep(0.01)
                if not app.busy: break
        else:
            raise SystemExit('timeout')


def mk(*p):
    d = os.path.join(tmp, *p); os.makedirs(d, exist_ok=True); return d


def pkg(name):
    pr = mk(name, 'print'); ds = [mk(name, f'part{i}') for i in (1, 2, 3)]
    DIRQ[:] = [pr] + ds


scan('start (locked)', app)
iddir, kfdir = mk('local', 'ident'), mk('usbstick')
w = gui_wizard.SetupWizard(app); app.update(); scan('wizard 0', w)
w.next(); scan('wizard 1', w)
w.s['id_dir'].set(iddir); w.s['kf_dir'].set(iddir); w.next()            # same folder → error message
w.s['kf_dir'].set(kfdir); w.next(); scan('wizard 2', w)
w.s['name'].set('Anna'); w.next(); scan('wizard 3', w)
pw = w.s['pw']; w.v_written.set(True); w.v_retype.set('wrong'); w.next()
w.v_retype.set(pw); w.next(); scan('wizard 4', w)
w.v_pin1.set('12345'); w.v_pin2.set('12345'); w.next()
w.v_pin1.set('864209'); w.v_pin2.set('864209'); w.next(); scan('wizard 5', w)
w.next(); wait(); scan('wizard 6', w)
pkg('bk'); w._backup(); wait(); w.next(); scan('wizard 7', w)
pkg('nf'); w._fido(); wait(3); w.next(); scan('wizard 8', w); w.next()
idp = os.path.join(iddir, 'Anna.said'); kfp = os.path.join(kfdir, 'Anna_identity.sakey')
ok_unlocked = app.vault is not None
for key in list(app.pages):
    app.show(key); app.update(); scan('page ' + key, app)
app.lock(); app.update(); scan('locked again', app)
app.v_id.set(idp); app.v_ikf.set(kfp); app.v_ipin.set('000000'); app.unlock(); wait()
app.v_ipin.set('864209'); app.unlock(); wait()
ok_relock = app.vault is not None
for key in list(app.pages):
    app.show(key); app.update(); scan('page ' + key + ' (unlocked)', app)
pwz = gui_wizard.PartnerWizard(app); app.update()
for i in range(4):
    scan(f'partner wizard {i}', pwz)
    if i == 0:
        pwz.next()
    elif i == 1:
        pwz.s['name'].set('Zed'); pwz.next()
try:
    pwz.destroy()
except tk.TclError:
    pass
app.toggle_theme(); app.update(); scan('theme button', app)
for kind, text in LOG:
    check('message ' + kind, text)

print(f"Wizard/unlock ok: {ok_unlocked} / {ok_relock}")
print(f"{len(LOG)} messages checked")
if found:
    for t, wh in sorted(found.items(), key=lambda x: x[1]):
        print(f"DEUTSCH [{wh}]: {t!r}")
    print("FEHLER VORHANDEN")
    sys.exit(1)
print("alle bestanden" if ok_unlocked and ok_relock else "FEHLER VORHANDEN")
sys.exit(0 if ok_unlocked and ok_relock else 1)
