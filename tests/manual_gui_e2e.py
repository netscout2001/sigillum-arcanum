"""Manueller End-to-End-Test der Oberfläche (öffnet ein Fenster). Aufruf: python tests/manual_gui_e2e.py"""
import os, sys, time, tempfile, tkinter as tk
tmp=tempfile.mkdtemp(); os.environ['SIGILLUM_LANG']='de'; os.environ['APPDATA']=tmp; os.environ['LOCALAPPDATA']=tmp; os.environ['SIGILLUM_NO_WIZARD']='1'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tkinter import messagebox, filedialog
LOG=[]; ANS=[True]
for n in ('showinfo','showerror','showwarning'):
    setattr(messagebox,n,lambda *a,_n=n,**k: LOG.append((_n,str(a[1])[:110] if len(a)>1 else '')))
messagebox.askyesno=lambda *a,**k: ANS[0]
from sigillum import gui, core, ratchet, handmode, codec
core.KDF_OPS, core.KDF_MEMLOG, core.ALLOWED_KDF = 1, 26, {(1,26)}
app=gui.App()
FACT={}
app.ask_factors=lambda *a, **k: FACT.get('v')
def wait():
    for _ in range(3000):
        app.update(); time.sleep(0.01)
        if not app.busy:
            for _ in range(5): app.update(); time.sleep(0.01)
            if not app.busy: return
    raise SystemExit('timeout')
def last(kind=None):
    l=[x for x in LOG if kind is None or x[0]==kind]; return l[-1][1] if l else None
def kf(name):
    p=os.path.join(tmp,name+'.sakey'); open(p,'wb').write(core.new_keyfile()); return p
KS, KA, KB = kf('gemeinsam'), kf('anna_id'), kf('ben_id')
PWS=core.generate_passphrase(); PWA=core.generate_passphrase(); PWB=core.generate_passphrase()
# R12-M1: neue Identität nur mit in der App gewürfelter Passphrase – selbst getippte Wortkette wird abgelehnt
PWX=' '.join(core.wordlist()[100:107]); filedialog.asksaveasfilename=lambda *a,**k: os.path.join(tmp,'self.said')
app.v_id.set(''); app.v_ipass.set(PWX); app.v_ipin.set('246813'); app.v_ikf.set(KA); app.v_name.set('Selbst')
LOG.clear(); app.new_identity()
for _ in range(300): app.update()
R12M1 = 'Erzeugen' in ([x[1] for x in LOG if x[0]=='showerror'] or [''])[-1] and not os.path.exists(os.path.join(tmp,'self.said'))
for _p in (PWS, PWA, PWB): app._generated.add(app._gen_tag(_p))
def ident(name, pw, k):
    app.v_id.set(os.path.join(tmp,name+'.said')); app.v_ipass.set(pw); app.v_ipin.set('246813'); app.v_ikf.set(k)
CRED={'Anna':(PWA,KA),'Ben':(PWB,KB)}
def become(name):
    app.lock(); wait(); ident(name,*CRED[name]); app.unlock(); wait(); assert app.vault and app.vault.identity.name==name, LOG[-3:]
res={}
res['R12-M1 neue Identität mit selbst getippter Passphrase abgelehnt']=R12M1
# --- H1: gemeinsame Schlüsseldatei vorher benutzt, dann als Identitätsdatei -> abgelehnt
app.v_pass.set(PWS); app.v_pin.set('135791'); app.v_kf.set(KS)
gui.set_text(app.t_plain,'Hallo gemeinsam'); app.v_mode.set('shared'); app.do_encrypt(); wait()
shared_cipher=gui.get_text(app.t_cipher)
LOG.clear(); ident('X', PWA, KS); app.v_name.set('X'); filedialog.asksaveasfilename=lambda *a,**k: os.path.join(tmp,'x.said')
app.new_identity(); wait(); res['H1 Identität mit gemeinsamer Schlüsseldatei abgelehnt']= 'gemeinsame' in (last('showerror') or '') and not os.path.exists(os.path.join(tmp,'x.said'))
LOG.clear(); ident('X', PWS, KA); app.new_identity(); wait(); res['H1 Identität mit gemeinsamer Passphrase abgelehnt']='Passphrase' in (last('showerror') or '')
# --- Identitäten anlegen
for n in ('Anna','Ben'):
    app.lock(); ident(n,*CRED[n]); app.v_name.set(n); filedialog.asksaveasfilename=lambda *a,_n=n,**k: os.path.join(tmp,_n+'.said')
    app.new_identity(); wait(); assert app.vault.identity.name==n, LOG[-2:]
    open(os.path.join(tmp,n+'.sapub'),'wb').write(app.vault.identity.public().to_bytes())
res['Identitätsfelder nach Entsperren geleert']= app.v_ipass.get()=='' and app.v_ipin.get()==''
# --- H1: Identitäts-Schlüsseldatei als gemeinsame -> abgelehnt
app.v_pass.set(PWS); app.v_pin.set('135791'); app.v_mode.set('shared'); gui.set_text(app.t_plain,'Hallo gemeinsam')  # Sperren leert die Felder (R11-M4)
LOG.clear(); app.v_kf.set(KB); app.do_encrypt(); wait(); res['H1 Identitäts-Schlüsseldatei als gemeinsame abgelehnt']='Identität' in (last('showerror') or '')
app.v_kf.set(KS); LOG.clear(); app.v_pass.set(PWB); app.do_encrypt(); wait(); res['H1 Identitäts-Passphrase als gemeinsame abgelehnt']='Passphrase' in (last('showerror') or '')
app.v_pass.set(PWS)
# --- Kontakte importieren + verifizieren per Dialog (M1, M5)
def import_and_verify(me, other, typed=None, method_idx=0):
    become(me)
    filedialog.askopenfilename=lambda *a,**k: os.path.join(tmp,other+'.sapub'); app.import_contact(); wait()
    app.tv.selection_set(app.tv.get_children()[0]); app.verify_contact()
    dlg=[w for w in app.winfo_children() if isinstance(w,tk.Toplevel)][-1]
    txt=[w for w in dlg.winfo_children() if isinstance(w,tk.Text)][0]
    fp=core.Contact.from_bytes(open(os.path.join(tmp,other+'.sapub'),'rb').read()).fingerprint()
    txt.insert('1.0', typed if typed is not None else fp.lower())
    btn=[w for f in dlg.winfo_children() for w in f.winfo_children() if isinstance(w,tk.Widget) and str(w.winfo_class())=='TButton' and w.cget('text')=='Prüfen'][0]
    btn.invoke(); wait()
become('Anna'); filedialog.askopenfilename=lambda *a,**k: os.path.join(tmp,'Ben.sapub'); app.import_contact(); wait()
app.tv.selection_set(app.tv.get_children()[0]); LOG.clear(); app.verify_contact()
dlg=[w for w in app.winfo_children() if isinstance(w,tk.Toplevel)][-1]
txt=[w for w in dlg.winfo_children() if isinstance(w,tk.Text)][0]; txt.insert('1.0','AAAA BBBB')
[w for f in dlg.winfo_children() for w in f.winfo_children() if str(w.winfo_class())=='TButton' and w.cget('text')=='Prüfen'][0].invoke(); wait()
res['M5 falscher Fingerabdruck abgelehnt']='NICHT' in (last('showerror') or '') and not app.vault.contacts()[0][1]
res['M5 Kontaktliste zeigt nur Anfang des Fingerabdrucks']= app.tv.item(app.tv.get_children()[0])['values'][1].endswith('…')
import_and_verify('Anna','Ben'); res['M5 korrekter Fingerabdruck verifiziert']=app.vault.contacts()[0][1]
import_and_verify('Ben','Anna')
blob=open(os.path.join(tmp,'Ben.said'),'rb').read(); res['M1 Kontaktbuch nicht im Klartext der Datei']= b'Anna' not in blob and b'verified' not in blob
# --- Unterhaltung über die Oberfläche
def send(frm,to,text):
    become(frm); app.v_mode.set('contact'); vals=list(app.cb_recip.cget('values'))
    app.cb_recip.current([i for i,x in enumerate(vals) if x.startswith(to)][0])
    gui.set_text(app.t_plain,text); app.do_encrypt(); wait(); return gui.get_text(app.t_cipher)
def recv(who,*c):
    become(who); gui.set_text(app.t_in,'\n\n'.join(c)); app.do_decrypt(); wait(); wait(); return gui.get_text(app.t_out)
ok=True
for i in range(2):
    ok &= f'Anna {i}' in recv('Ben', send('Anna','Ben',f'Anna {i}'))
    ok &= f'Ben {i}' in recv('Anna', send('Ben','Anna',f'Ben {i}'))
res['Unterhaltung mit Schlüsselwechsel']=ok
m=send('Anna','Ben','metadaten')
mb=codec.decode(m); pa=core.Contact.from_bytes(open(os.path.join(tmp,'Anna.sapub'),'rb').read())
res['M2 keine Kennung im Geheimtext']= pa.fp_raw()[:16] not in mb and pa.fp_raw() not in mb
# --- Lücke über GUI: Nein -> nichts geändert
recv('Ben',m); m1=send('Ben','Anna','eins'); recv('Ben',send('Anna','Ben','dazwischen')); m2=send('Ben','Anna','zwei')
become('Anna'); before=open(os.path.join(tmp,'Anna.said'),'rb').read(); ANS[0]=False
gui.set_text(app.t_in,m2); app.do_decrypt(); wait(); wait()
res['Lücke erkannt, Nein -> Datei unverändert']= open(os.path.join(tmp,'Anna.said'),'rb').read()==before and gui.get_text(app.t_out)==''
ANS[0]=True; out=recv('Anna',m2,m1); res['Stapel sortiert']= out.find('eins')<out.find('zwei') and 'NICHT' not in out
# --- L1: eigene gemeinsame Nachricht zurückgespiegelt
app.v_pass.set(PWS); app.v_pin.set('135791'); app.v_kf.set(KS)
gui.set_text(app.t_in,shared_cipher); app.do_decrypt(); wait()
res['L1 zurückgespiegelte eigene Nachricht erkannt']='DIESEM Gerät' in gui.get_text(app.t_out)
# --- Hand-Modus: Register in Identität, Wiederverwendung hart abgelehnt, Fälschung erkannt
sh=handmode.Sheet.new(4); app.v_sheet.set(sh.id); gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hplain,'Treffen um 14:30')
app.hand_encrypt(); wait(); hc=gui.get_text(app.t_hcipher)
res['L7 Blatt im verschlüsselten Register']= ratchet.Vault.open(open(os.path.join(tmp,'Anna.said'),'rb').read(),PWA,'246813',open(KA,'rb').read()).sheet_used(sh.id)
gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hplain,'zweites Mal'); LOG.clear(); app.hand_encrypt(); wait()
res['Blatt-Wiederverwendung hart abgelehnt']='bereits verwendet' in (last('showerror') or '')
LOG.clear(); gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hcipher, hc); app.hand_decrypt(); wait()
res['Hand entschlüsseln (eigene Nachricht, keine Warnung)']= gui.get_text(app.t_hplain)=='TREFFEN UM 14:30' and not last('showwarning')
res['R2 Blattcode nach Entschlüsseln geleert']= gui.get_text(app.t_pad)==''
v=codec.text_to_values(hc); v[13]^=6; gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hcipher, codec.values_to_glyphs(v)); LOG.clear(); app.hand_decrypt(); wait()
res['H2 Fälschung im Hand-Modus erkannt']='FEHLGESCHLAGEN' in (last('showerror') or '') and gui.get_text(app.t_hplain)==''
# --- R2-1: Empfänger vermerkt das Blatt und kann es nicht für die Antwort nehmen
become('Ben'); app.v_sheet.set(sh.id); gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hcipher, hc); app.hand_decrypt(); wait()
okdec = gui.get_text(app.t_hplain)=='TREFFEN UM 14:30'
benv = ratchet.Vault.open(open(os.path.join(tmp,'Ben.said'),'rb').read(),PWB,'246813',open(KB,'rb').read())
gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hplain,'Antwort'); LOG.clear(); app.hand_encrypt(); wait()
res['R2-1 Empfänger vermerkt Blatt, Antwort damit abgelehnt']= okdec and benv.sheet_used(sh.id) and 'bereits verwendet' in (last('showerror') or '')
# --- R2-2: falsche Blatt-Nr. abgelehnt, nichts vermerkt
sh2=handmode.Sheet.new(4); wrong=handmode.Sheet.new(2).id; app.v_sheet.set(wrong); gui.set_text(app.t_pad, sh2.code())
gui.set_text(app.t_hplain,'Test'); LOG.clear(); app.hand_encrypt(); wait()
benv = ratchet.Vault.open(open(os.path.join(tmp,'Ben.said'),'rb').read(),PWB,'246813',open(KB,'rb').read())
res['R2-2 falsche Blatt-Nr. abgelehnt, nichts vermerkt']= 'passt nicht' in (last('showerror') or '') and not benv.sheet_used(wrong) and not benv.sheet_used(sh2.id)
# --- R2-1: andere Nachricht mit schon benutztem Blatt -> Warnung
app.v_sheet.set(sh2.id); gui.set_text(app.t_pad, sh2.code()); gui.set_text(app.t_hplain,'Erste'); app.hand_encrypt(); wait()
other = codec.values_to_glyphs(handmode.encrypt('Zweite', sh2))
gui.set_text(app.t_pad, sh2.code()); gui.set_text(app.t_hcipher, other); LOG.clear(); app.hand_decrypt(); wait()
res['R2-1 Wiederverwendung beim Entschlüsseln gewarnt']= 'ANDERE Nachricht' in (last('showwarning') or '') and gui.get_text(app.t_hplain)=='ZWEITE'
# --- R3-2: dieselbe Hand-Nachricht ein zweites Mal -> "bereits entschlüsselt"
app.v_sheet.set(sh.id); gui.set_text(app.t_pad, sh.code()); gui.set_text(app.t_hcipher, hc); LOG.clear(); app.hand_decrypt(); wait()
res['R3-2 Hand-Wiederholung: bereits entschlüsselt']= 'bereits entschlüsselt' in (last('showwarning') or '') and gui.get_text(app.t_hplain)=='TREFFEN UM 14:30'
# --- R2-3: Lückentext bleibt kurz
r_big={'gap':list(range(2,22)),'gap_count':2**62}
res['R2-3 Lückentext kurz']= len(gui.gap_text(r_big))<80 and gui.gap_text({'gap':[3,4],'gap_count':2})=='Nachricht Nr. 3, 4'
# --- Hinweis: keine rohen Schlüsseldatei-Kennungen in den Einstellungen
cfgtxt=open(os.path.join(tmp,'SigillumArcanum','einstellungen.json')).read()
raw=[core.keyfile_digest(open(k,'rb').read()) for k in (KS,KA,KB)]
res['Einstellungen ohne rohe Schlüsseldatei-Kennung']= not any(r in cfgtxt for r in raw) and app.cfg.has('identity_kf', raw[1])
# --- R3-1: Kontakt-Nachricht zweimal einfügen -> "schon geöffnet"
mm=send('Ben','Anna','Wiederholungstest'); out1=recv('Anna',mm); out2=recv('Anna',mm)
# R12-N1: Einmal-Schlüssel ist nach dem ersten Öffnen gelöscht – Wiederholung erkannt, Inhalt nicht mehr lesbar
res['R3-1 Kontakt-Wiederholung: schon geöffnet (Einmal-Schlüssel gelöscht)']= 'schon geöffnet' not in out1 and 'Wiederholungstest' in out1 and 'schon geöffnet' in out2 and 'Wiederholungstest' not in out2
become('Anna')
# --- YubiKey (Software-Nachbildung statt Hardware)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from softtoken import SoftToken
from sigillum import notfall, shamir
import glob
TOK=SoftToken(); gui.fidokey.Fido2Token=lambda ui=None: TOK
messagebox.askokcancel=lambda *a,**k: True
DIRQ=[]
filedialog.askdirectory=lambda *a,**k: DIRQ.pop(0) if DIRQ else ''
def pkg(name, files=True):
    """Druckordner + je ein eigener Ordner pro Teil; liefert (Druckordner, [Teilordner])."""
    base=os.path.join(tmp,name); os.mkdir(base); pr=os.path.join(base,'druck'); os.mkdir(pr)
    ds=[os.path.join(base,f'teil{i}') for i in (1,2,3)]
    for d in ds: os.mkdir(d)
    DIRQ[:]=[pr]+(ds if files else [])
    return pr, ds
def read_parts(ds): return [open(f,'rb').read() for d in ds for f in sorted(glob.glob(os.path.join(d,'*.sashare')))]
become('Anna'); annap=os.path.join(tmp,'Anna.said'); old_copy=open(annap,'rb').read(); FACT['v']=(PWA,'246813')
pr1, ds1 = pkg('pk1'); ANS[0]=True; app.v_ikf.set(KA); app.fido_enable(); wait(); wait()
parts1=read_parts(ds1)
res['Y1 Einschalten: Modus 5, je Teil eigener Ordner, PDFs gelöscht']= ratchet.file_mode(open(annap,'rb').read())==5 and len(parts1)==3 and os.listdir(pr1)==[] and app.vault.fido
app.lock(); wait(); ident('Anna',*CRED['Anna']); app.unlock(); wait()
res['Y2 Entsperren mit YubiKey']= app.vault is not None and app.vault.fido and '(YubiKey)' in app.l_vault.cget('text')
app.lock(); wait(); ident('Anna',*CRED['Anna']); TOK.entered='000000'; LOG.clear(); app.unlock(); wait(); TOK.entered=TOK.pin
res['Y3 falsche FIDO-PIN: gesperrt, Meldung']= app.vault is None and 'PIN' in (last('showerror') or '')
app.lock(); wait(); ident('Anna',*CRED['Anna']); real=TOK.creds; TOK.creds={}; LOG.clear(); app.unlock(); wait(); TOK.creds=real
res['Y4 fremder YubiKey abgelehnt']= app.vault is None and 'gehört nicht' in (last('showerror') or '')
def recovery(parts, pick):
    app.lock(); wait(); app.v_id.set(annap); app.v_ipass.set(''); app.v_ipin.set(''); app.v_ikf.set('')
    app.unlock_recovery(); dlg=[w for w in app.winfo_children() if isinstance(w,tk.Toplevel)][-1]
    ents=[w for f in dlg.winfo_children() for w in f.winfo_children() if str(w.winfo_class())=='TEntry']
    ents[0].insert(0, CRED['Anna'][0]); ents[1].insert(0, '246813')   # R11-M1: Felder im Notfall-Dialog
    txt=[w for f in dlg.winfo_children() for w in ([f]+list(f.winfo_children())) if isinstance(w,tk.Text)][0]
    txt.insert('1.0','\n\n'.join(app.share_to_text(p) for p in parts))
    def click():
        tops=[w for w in app.winfo_children() if isinstance(w,tk.Toplevel) and 'verbraucht' in w.title()]
        if not tops: return app.after(100, click)
        b=[w for w in tops[-1].winfo_children() if str(w.winfo_class())=='TButton' and w.cget('text').startswith(pick)]
        b[0].invoke()
    app.after(300, click)
    [w for f in dlg.winfo_children() for w in f.winfo_children() if str(w.winfo_class())=='TButton' and w.cget('text')=='Entsperren'][0].invoke()
    for _ in range(4): wait()
kfA=open(KA,'rb').read()
pr2, ds2 = pkg('pk2'); recovery(parts1[1:], 'Bisherigen')
parts2=read_parts(ds2); blob=open(annap,'rb').read()
try: ratchet.Vault.open(blob, CRED['Anna'][0], '246813', kfA, code=notfall.open_parts(parts1[:2])[1:]); oldok=True
except core.SigillumError: oldok=False
v5=ratchet.Vault.open(blob, CRED['Anna'][0], '246813', kfA, code=notfall.open_parts(parts2[:2])[1:])
res['Y5 Notfall: entsperrt, Paket erneuert, alter Code ungültig, Vermerk gelöscht']= app.vault is not None and not oldok and v5.fido and not v5.recovery_pending and app._recovery_kf is None
before=open(annap,'rb').read(); recovery(parts2[:2], 'Abbrechen')
vpend=ratchet.Vault.open(open(annap,'rb').read(), CRED['Anna'][0], '246813', kfA, prf_fn=TOK.derive)
res['Y6 Notfall ohne Erneuerung: gesperrt, aber in der Datei vermerkt (R4-2)']= app.vault is None and vpend.recovery_pending
# R4-2: nächstes normales Entsperren verlangt die Erneuerung
pr2b, ds2b = pkg('pk2b')
def clickkeep():
    tops=[w for w in app.winfo_children() if isinstance(w,tk.Toplevel) and 'verbraucht' in w.title()]
    if not tops: return app.after(100, clickkeep)
    [w for w in tops[-1].winfo_children() if str(w.winfo_class())=='TButton' and w.cget('text').startswith('Bisherigen')][0].invoke()
app.after(300, clickkeep); ident('Anna',*CRED['Anna']); app.v_id.set(annap); app.unlock()
for _ in range(4): wait()
parts2=read_parts(ds2b)
v6=ratchet.Vault.open(open(annap,'rb').read(), CRED['Anna'][0], '246813', kfA, prf_fn=TOK.derive)
res['Y6b Vermerk erzwingt Erneuerung beim nächsten Entsperren']= app.vault is not None and not v6.recovery_pending and len(parts2)==3
TOK2=SoftToken(); gui.fidokey.Fido2Token=lambda ui=None: TOK2
pr3, ds3 = pkg('pk3'); recovery(parts2[:2], 'Neuen')
blob=open(annap,'rb').read()
try: ratchet.Vault.open(blob, CRED['Anna'][0], '246813', kfA, prf_fn=TOK.derive); oldkey=True
except core.SigillumError: oldkey=False
res['Y7 Notfall mit neuem Key: alter Key gesperrt']= app.vault is not None and not oldkey and ratchet.Vault.open(blob, CRED['Anna'][0], '246813', kfA, prf_fn=TOK2.derive).fido
parts3=read_parts(ds3)
pr4, ds4 = pkg('pk4'); TOK2.entered='0'; recovery(parts3[:2], 'Bisherigen'); TOK2.entered=TOK2.pin
res['Y8 Key-Fehler bei Pflicht-Erneuerung: gesperrt, kein Paket']= app.vault is None and not any(os.listdir(d) for d in [pr4]+ds4)
# nach Y8 steht der Notfall-Vermerk noch in der Datei -> Entsperren verlangt zuerst die Erneuerung (R4-2)
pr8, ds8 = pkg('pk8'); app.after(300, clickkeep); become('Anna')
for _ in range(3): wait()
res['Y8b nach Fehler: nächstes Entsperren erzwingt Erneuerung']= len(read_parts(ds8))==3 and not app.vault.recovery_pending
pr5, ds5 = pkg('pk5'); before=open(annap,'rb').read(); ANS[0]=False; app.fido_renew(); wait(); ANS[0]=True
res['Y9 Druck nicht bestätigt: verworfen, Datei unverändert']= not any(os.listdir(d) for d in [pr5]+ds5) and open(annap,'rb').read()==before
# R4-1: zwei Teile in denselben Ordner -> abgelehnt, alles gelöscht
base=os.path.join(tmp,'pk6'); os.mkdir(base); pr6=os.path.join(base,'druck'); os.mkdir(pr6); same=os.path.join(base,'x'); os.mkdir(same)
DIRQ[:]=[pr6, same, same]; LOG.clear(); app.fido_renew(); wait()
res['Y10 R4-1 gleicher Ordner für zwei Teile abgelehnt, nichts liegen geblieben']= any('EIGENEN Ordner' in t for k,t in LOG) and os.listdir(pr6)==[] and os.listdir(same)==[] and open(annap,'rb').read()==before
# R4-5: verfälschter Teil -> unverfälschtes Paar wird gefunden
b=bytearray(parts3[0]); b[30]^=1; forged=bytes(b[:-4])+shamir._chk(bytes(b[:-4]))
res['Y11 R4-5 verfälschter Teil erkannt, Paar der echten Teile benutzt']= notfall.open_parts([forged, parts3[1], parts3[2]])==notfall.open_parts(parts3[1:])
gui.set_text(app.t_shares, '\n\n'.join(app.share_to_text(p) for p in parts3[:2]))
rest=os.path.join(tmp,'restored.sakey'); filedialog.asksaveasfilename=lambda *a,**k: rest; app.combine_shares()
res['Y12 Backup-Tab: Schlüsseldatei aus Notfall-Paket']= open(rest,'rb').read()==kfA
# R8-H4: Schlüsseldatei-Backup mit einem verfälschten Teil -> stimmiges Paar benutzt, Teil gemeldet
kparts=shamir.split(kfA); fb=bytearray(kparts[1][:-4]); fb[40]^=0x33; kparts[1]=bytes(fb)+shamir._chk(bytes(fb))
gui.set_text(app.t_shares, '\n\n'.join(app.share_to_text(p) for p in kparts))
rest2=os.path.join(tmp,'restored2.sakey'); filedialog.asksaveasfilename=lambda *a,**k: rest2; LOG.clear(); app.combine_shares()
res['R8-H4 verfälschter Backup-Teil gemeldet, Schlüsseldatei korrekt']= open(rest2,'rb').read()==kfA and 'Teil 2 passt nicht' in (last('showwarning') or '')
cp=os.path.join(tmp,'Anna_alt.said'); open(cp,'wb').write(old_copy); app.lock(); wait()
ident('Anna',*CRED['Anna']); app.v_id.set(cp); LOG.clear(); app.unlock(); wait()
res['Y13 Warnung bei alter Kopie ohne YubiKey']= any(k=='showwarning' and 'YubiKey geschützt' in t for k,t in LOG)
# R4-6: alte Kopien finden und löschen
become('Anna'); sub=os.path.join(tmp,'sicherung'); os.mkdir(sub); cp2=os.path.join(sub,'Anna_kopie.said'); open(cp2,'wb').write(old_copy)
DIRQ[:]=[sub]; ANS[0]=True; app.find_old_copies()
res['Y14 R4-6 alte Kopien gefunden und gelöscht, aktuelle Datei bleibt']= not os.path.exists(cp) and not os.path.exists(cp2) and os.path.exists(annap) and os.path.exists(os.path.join(tmp,'Ben.said'))
ANS[0]=True; app.fido_disable(); wait()
res['Y15 Ausschalten: Modus 3, Markierung entfernt']= ratchet.file_mode(open(annap,'rb').read())==3 and not app.cfg.had_fido(app.vault.identity.public().fp_raw())
pr7, ds7 = pkg('pk7'); app.v_ikf.set(KB); LOG.clear(); app.fido_enable(); wait(); app.v_ikf.set(KA)
res['Y16 Paket nur mit passender Schlüsseldatei']= 'gehört nicht zu dieser Identität' in (last('showerror') or '') and not app.vault.fido and not any(os.listdir(d) for d in [pr7]+ds7)
DIRQ[:]=[]
# Schlüsseldatei-Backup über denselben sicheren Ablauf
prb, dsb = pkg('bk'); filedialog.askopenfilename=lambda *a,**k: KS; app.split_keyfile()
import sigillum.shamir as SH
res['Y17 Schlüsseldatei-Backup: Teile getrennt, PDFs gelöscht']= os.listdir(prb)==[] and SH.combine(read_parts(dsb)[1:])==open(KS,'rb').read()
# --- R6-1: Zufallsblatt nur zum Drucken, danach gelöscht; Cloud-Ordner wird nachgefragt
padd=os.path.join(tmp,'druck_blatt'); os.mkdir(padd); DIRQ[:]=[padd]; ANS[0]=True; app.v_blocks.set(4); app.make_pad()
res['R6-1 Zufallsblatt: PDF nach dem Drucken gelöscht']= os.listdir(padd)==[]
cloud=os.path.join(tmp,'OneDrive'); os.mkdir(cloud); DIRQ[:]=[cloud]; ANS[0]=False; app.make_pad(); ANS[0]=True
res['R6-1 Cloud-Ordner abgelehnt, nichts geschrieben']= os.listdir(cloud)==[]
# --- R6-3: unerwarteter PDF-Fehler -> nichts bleibt liegen, Pflicht-Erneuerung sperrt
import sigillum.pdfout as PO
orig=PO.package_sheet; cnt={'n':0}
def flaky(*a, **k):
    cnt['n']+=1
    if cnt['n']==2: raise RuntimeError('kaputt')
    return orig(*a, **k)
PO.package_sheet=flaky; gui.pdfout.package_sheet=flaky
DIRQ[:]=[]; become('Anna'); ANS[0]=True; app.v_ikf.set(KA)
pr9, ds9 = pkg('pk9'); app.fido_enable(); wait(); wait()
PO.package_sheet=orig; gui.pdfout.package_sheet=orig
res['R6-3 PDF-Fehler: nichts liegen geblieben, nicht umgestellt']= not any(os.listdir(d) for d in [pr9]+ds9) and not app.vault.fido
# --- R7: vorhandene Datei wird nie überschrieben oder gelöscht
fx=os.path.join(tmp,'fremd'); os.mkdir(fx); fremd=os.path.join(fx,'backup_ZZ0001_teil_1.pdf'); open(fremd,'wb').write(b'MEINE DATEI')
DIRQ[:]=[fx]; ok=app._hand_out_parts(SH.split(open(KS,'rb').read()), 'ZZ0001', 'Backup', lambda p,t,i,n,k,_t: PO.share_sheet(p,t,i,n,k), 'x')
res['R7 fremde Datei mit gleichem Namen bleibt unangetastet']= ok is False and open(fremd,'rb').read()==b'MEINE DATEI' and os.listdir(fx)==['backup_ZZ0001_teil_1.pdf']
# --- L3: kein Rückgängig
gui.set_text(app.t_plain,'geheim'); gui.set_text(app.t_plain,'')
try: app.t_plain.edit_undo(); undone=gui.get_text(app.t_plain)
except tk.TclError: undone=''
res['L3 Strg+Z stellt Klartext nicht wieder her']= undone==''
# --- Externe Änderung der Identitätsdatei
p=os.path.join(tmp,'Anna.said'); d=bytearray(open(p,'rb').read()); open(p,'wb').write(bytes(d)+b'')
os.utime(p); open(p,'ab').write(b'')
blob=open(p,'rb').read(); open(p,'wb').write(blob[:-1]+bytes([blob[-1]^1]))
LOG.clear(); app.v_mode.set('contact'); app.cb_recip.current(0); gui.set_text(app.t_plain,'x'); app.do_encrypt(); wait()
res['Externe Änderung erkannt und gesperrt']= app.vault is None and 'außerhalb' in (last('showerror') or '')
app.on_close()
w=max(len(k) for k in res)
for k,v in res.items(): print(f"{k:<{w}}  {'OK' if v else 'FEHLER'}")
print('alle bestanden' if all(res.values()) else 'FEHLER VORHANDEN')
sys.exit(0 if all(res.values()) else 1)
