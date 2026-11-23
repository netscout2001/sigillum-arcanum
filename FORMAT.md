# Sigillum Arcanum – Format v3 (App-Version 11.3, für Prüfer)

*English version: [`FORMAT.en.md`](FORMAT.en.md)*

Ausgerichtet an BSI TR-02102-1 (Version 2026-01). Primitive: AES-256-GCM-SIV (RFC 8452), HKDF-SHA-512 (RFC 5869),
SHA3-256/-512, SHAKE256, Argon2id, ML-KEM-1024 (FIPS 203) + ECDH-brainpoolP512r1 (RFC 5639), ML-DSA-87 „hedged“
(FIPS 204) + ECDSA-brainpoolP512r1 mit SHA3-512. Post-Quanten-Verfahren werden ausschließlich hybrid eingesetzt.
`h3(label, x, n)` = erste n Byte von SHA3-256(lp(label) | x) (n ≤ 32). Dateien der Formate v1/v2 werden abgelehnt.

Alle Mehrbyte-Zahlen Big-Endian. Jede Datei beginnt mit mindestens 6 Byte Kopf ("SA" | Version | Modus | …);
kürzere werden mit klarer Meldung abgelehnt (Befund R8-N1). `lp(x)` = 4-Byte-Länge + x. Texte UTF-8.
Format v3 ist in 11.2 und 11.3 identisch; 11.3 ergänzt nur die Sprache der Oberfläche.

## Schlüsselableitung (Modus 1 und 3)
```
keyfile  = "SAKEY2\0\0" | 32 Zufallsbytes | h3("SIGILLUM-KEYFILE-CHK", vorherige 40 Bytes, 4)
pw'      = NFC(pw).casefold(), an Leerraum getrennt, mit genau einem Leerzeichen verbunden
material = "SIGILLUM-ARCANUM-v3\0" | lp(zweck) | lp(pw') | lp(NFC(pin).strip()) | lp(keyfile_secret32)
           zweck = "shared" (Modus 1) | "identity" (Modus 3)
key      = Argon2id(material, salt16, ops = 4, mem = 2^30)
```
Beim Lesen werden ausschließlich ops = 4, memlog = 30 angenommen.
Beim Erzeugen: Passphrase aus ≥ 6 VERSCHIEDENEN Wörtern der EFF-Liste (77,5 Bit; seit 11.2 gezogen ohne Zurücklegen,
Wiederholungen zählen nicht; eine neue Identität nur mit in der App gewürfelter Passphrase). App-PIN ≥ 6 Zeichen und
nicht naheliegend (seit 11.2, core.pin_problem: ≤ 2 verschiedene Zeichen, Zahlen-/Buchstaben-/Tastenfolgen und
Ziffernblock-Wege, Wiederholungen mit Periode 2–4, Spiegelmuster, verschränkte Muster, Datumsangaben mit und ohne
Trennzeichen, häufige Wörter auch in Leetspeak; nur ASCII-Ziffern gelten als Ziffern; sperrt ~17 % der 6-stelligen
Zifferncodes; TR-02102-1 Bem. 6.2). Da die PIN offline angreifbar ist, ruht ihr Schutz auf den Besitzfaktoren (Bem. 6.4 (iii)).
Die App erzwingt verschiedene Schlüsseldateien und Passphrasen für Modus 1 und 3.

## Nutzlast (innen)
```
0x03 | flags(1) | unixzeit(8) | msgid(16) | absender(16) | textlänge(4) | text | 0x00-Auffüllung
```
Aufgefüllt auf 128 · 2^k Bytes; Auffüllbytes müssen 0 sein. Text ≤ 256 KiB.
absender = Kanalkennung HMAC-SHA256(Geräte-Geheimnis, "SIGILLUM-CHAN" | Schlüsseldatei-Kennung)[0:16] (Modus 1)
           bzw. die ersten 16 Byte des Absender-Fingerabdrucks (Modus 4).

## Modus 1 – gemeinsamer Schlüssel
```
header = "SA" | 0x03 | 0x01 | ops | memlog | salt16 | nonce12
blob   = header | AES-256-GCM-SIV(key, nonce, inner, aad = header)         (Prüfwert 128 Bit)
```

## Modus 3 – Identitätsdatei
```
header = "SA" | 0x03 | 0x03 | ops | memlog | salt16 | nonce12
inhalt = "SAPRV5" | lp(name) | kem_seed32 | ecdsa_seed32 | mldsa87_seed32 | lp(zustand_json)
zustand = {"v":4, "book": {fp: {name, pub, verified, method, …}}, "contacts": {fp: Schlüsselstand},
           "sheets": {Blatt-Nr.: Nachrichtenkennung}, "sheets_opened": {Blatt-Nr.: Anzahl Entschlüsselungen},
           "seen": {fp: {"ids": [h3("SIGILLUM-SEEN", msgid, 16)], "ts": Untergrenze}}}
           "chk": {"a": hex(h3("SIGILLUM-v11-A-CHECK", A, 32)), "d": hex(h3("SIGILLUM-v11-A2-CHECK", A2, 32)),
                   "pw_salt": hex16,
                   "pw": hex(HMAC-SHA256(pw_salt, pw'))},
           "partners": {pid16hex: {"name", "kf": hex(Schlüsseldatei44), "pw": pw', "pin", "created", "last_used"}},
           "recovery_pending"?: bool,
           "gen"?: Schreib-Generation (11.2, R12-N4; fehlt = 0; jedes Speichern +1),
           "spent"?: [h3("SIGILLUM-SPENT", header, 16)] (11.2, R12-N1; höchstens 2000)}
           ("seen" höchstens 2000 Kennungen je Kontakt, bleibt bei Neustart und Entfernen des Kontakts erhalten;
           höchstens 64 Partner; jeder Partner-Eintrag muss beim Laden dieselben Regeln erfüllen wie beim Anlegen:
           gültiger Name, Schlüsseldatei, Diceware-Passphrase aus ≥ 6 Listenwörtern in kanonischer Form, PIN ≥ 6, nie
           die Passphrase der Identität (beim Laden bewusst ohne die strengere 11.2-Regel „keine Wiederholung“, damit
           sich niemand aussperrt); jede Abweichung im Zustand wird abgelehnt – keine Übernahme älterer Formen)
chk.a     : weist vor sicherheitskritischen Änderungen nach, dass Passphrase + PIN + Schlüsseldatei stimmen
            (Schritt-Bestätigung), auch in einer Alltags-Sitzung ohne Passphrase.
chk.d     : Prüfwert für A2 (Alltags-Schlüssel, Zweck "daily"); geprüft beim Alltags-Entsperren, in full_keys und
            vor jedem Schreiben einer Alltags-Hülle (protect) – ein falsches A2 kann so keine unbrauchbare Hülle
            erzeugen. Seit 11.1; Identitäten aus 11.0 haben ihn noch nicht und bekommen ihn beim nächsten
            Alltags-Entsperren oder bei der nächsten Schritt-Bestätigung (jeweils erst, wenn A2 bewiesen ist).
chk.pw    : Befund H1 – gemeinsame Passphrase darf nicht die der Identität sein (Prüfung ohne Passphrase in der
            Sitzung). Liegt nur verschlüsselt im Inhalt. Diceware ≥ 77,5 Bit (≈ 2^76,5 SHA-256-Aufrufe im Mittel) ist
            mit diesem schnellen Hash wirtschaftlich nicht durchprobierbar; das liegt unter den 120 Bit aus TR-02102-1
            Bem. 6.4 (iii) – wer den entschlüsselten Zustand hat, hat aber ohnehin alle Schlüssel der Identität.
```
Zurückschreiben: gleiches Salz und Schlüssel, neue Zufalls-Nonce (AES-GCM-SIV: auch eine zufällige
Nonce-Wiederholung verletzt weder Vertraulichkeit noch Integrität, TR-02102-1 Abschn. 3.1.2), atomarer
Dateiersatz; vorher Prüfung, dass die Datei seit dem Öffnen unverändert ist.

## Selbsttest beim Start
RFC-8452-Vektor (AES-GCM-SIV), FIPS-202-Vektor (SHA3-256), HKDF-SHA-512 gegen eine unabhängige hmac-Rechnung,
Hybrid-KEM gegen tests/vectors/hkem_v3.txt (Schlüssel aus Seed und Entkapselung), Signaturschlüssel aus festen Seeds,
Rundlauf und Ablehnung verfälschter Signaturen. Seit 11.2 zusätzlich Prüfwerte fremder Implementierungen
(sigillum/data/kat_fremd.json, erzeugt ohne OpenSSL/libsodium): ECDSA-brainpoolP512r1-SHA3-512 aus eigener
Kurvenarithmetik nach RFC 5639, ML-DSA-87-Schlüssel und -Signatur aus dilithium-py (FIPS 204, mit Kontext),
Argon2id aus argon2-cffi (RFC 9106). Bei Abweichung startet die App nicht.

## Modus 5 – Identitätsdatei mit YubiKey (optional, v11: Alltag ohne Passphrase)
```
A       = Argon2id wie Modus 3 (Zweck "identity")                         (Passphrase + PIN + Schlüsseldatei)
A2      = Argon2id("SIGILLUM-ARCANUM-v3\0" | lp("daily") | lp(NFC(pin).strip()) | lp(keyfile_secret32), salt16,
          ops = 4, mem = 2^30)                                              (PIN + Schlüsseldatei, OHNE Passphrase)
kopf    = "SA" | 0x03 | 0x05 | ops | memlog | salt16 | prf_s32 | anzahl(1) | hülle* | nonce12
hülle   = typ(1) | meta_len(2) | meta | nonce12 | AES-256-GCM-SIV(KEK, M, aad)(48)
          typ 3 = Alltag (YubiKey): meta = cred_id (1–1023 Byte); geheimnis = WebAuthn-PRF(prf_s) (32 Byte); basis = A2
          typ 2 = Notfall:          meta = code_id16;              geheimnis = Notfall-Code (32 Byte);    basis = A
          typ 1 = YubiKey-Hülle bis Version 10.1 (Basis A) – wird abgelehnt („ältere App-Version“)
KEK     = HKDF-SHA-512(ikm = basis | geheimnis, salt = leer,
                       info = "SIGILLUM-v3-slot" | typ | h3("SIGILLUM-v3-slot-meta", meta, 32))
aad     = kopf[0:6] | salt16 | prf_s32 | typ | meta
inhalt  = AES-256-GCM-SIV(M, nonce, wie Modus 3, aad = kopf)
```
Genau 1 Notfall-Hülle und 1–4 Alltags-Hüllen, keine doppelte cred_id; alles andere wird abgelehnt.
M und prf_s werden bei jeder Änderung der Hüllen neu gewürfelt. Jede Änderung (ein/aus, Key ersetzen, Paket erneuern)
verlangt A und A2 aus Passphrase + PIN + Schlüsseldatei; A wird gegen chk.a geprüft, sonst wird nichts geändert.
Faktoren im Alltag: Schlüsseldatei (Besitz), YubiKey (Besitz, Hardware), FIDO-PIN (Wissen, im Key gegen Durchprobieren
geschützt), App-PIN (Wissen). Ohne YubiKey-Geheimnis fehlen einem Offline-Angreifer 256 Bit. FIDO-Zugang: RP-ID "sigillum-arcanum.invalid"
(RFC 2606, nie auflösbar), authenticatorAttachment "cross-platform", Hinweis "security-key", Transport "usb",
residentKey "discouraged", credProtect "userVerificationRequired" (erzwungen), userVerification "required"; das
UV-Flag der Antwort wird geprüft. Zustand "recovery_pending" (bool) = Notfall-Code benutzt, Erneuerung ausstehend.
PRF nach WebAuthn: hmac-secret-Salz = SHA-256("WebAuthn PRF" | 0x00 | prf_s); hmac-secret rechnet im YubiKey mit
HMAC-SHA-256 (CTAP 2.1, nicht änderbar; HMAC-SHA-256 ist nach TR-02102-1 Tab. 5.1 empfohlen).

## Notfall-Paket
```
teil  = "SASHP3" | satz4 | x | k | n | y160 | bind32 | h3("SIGILLUM-SHARE-CHK", alles davor, 4)
         Shamir 2 aus 3 über F_p, p = 2^1279 - 1, nach TR-02102-1 Kap. 7 (Tab. 7.1/7.2):
         a0 = int(Identitäts-Schlüsseldatei44 | code_id16 | Notfall-Code32), a1 gleichverteilt aus {0..p-1},
         y = f(x) mod p (Big-Endian, 160 Byte), x = 1..3
bind32   = h3("SIGILLUM-SHRC", satz4 | Schlüsseldatei | code_id | Code, 32), in jedem Teil gleich
```
Beim Zusammensetzen muss das Ergebnis zum Bindewert passen; mit drei Teilen wird ein verfälschter Teil übergangen.
Teile verschiedener Arten (SASHP1/SASHP3) oder Sätze werden nicht gemischt; ältere Formate (SASHR1–3) werden abgelehnt.
Beim Zusammensetzen muss a0 < 2^(8·92) sein, sonst gelten die Teile als unpassend.
Ausgabe: PDFs zum Drucken (nach Bestätigung überschrieben und gelöscht), Dateien nur optional, je Teil ein eigener Ordner.

## Hybrid-KEM (ML-KEM-1024 + ECDH-brainpoolP512r1)
```
expand(seed32): e = SHAKE256(lp("SIGILLUM-v3-HKEM-expand") | seed, 160)
                sk_M = ML-KEM-1024.KeyGen_internal(d = e[0:32], z = e[32:64])
                d_X  = (int(e[64:160]) mod (q - 1)) + 1                     (768 Bit -> Abweichung < 2^-256)
ek1 = pk_M(1568)        ek2 = 04 | x64 | y64 (129)        pk = ek1 | ek2 (1697)
Kapselung: (K1, c1) = ML-KEM-1024.Encaps(ek1); Wegwerf-Schlüssel e; c2 = e·G (129); K2 = x(e·ek2) (64)
ct  = c1(1568) | c2(129) (1697)
K   = HKDF-SHA-512(ikm = K1 | K2 | c1 | c2 | ek1 | ek2, salt = leer, info = domain_sep, L = 32)
domain_sep = "SIGILLUM-ARCANUM-v3/HKEM/ML-KEM-1024+ECDH-brainpoolP512r1/SP800-227-KeyCombine/HKDF-SHA-512"
```
KeyCombine nach NIST SP 800-227, Abschn. 4.6.2, Gl. (15): H(K1, K2, c1, c2, ek1, ek2, domain_sep), H = KDF – nach
TR-02102-1 Tab. 2.1 zulässig. Alle Eingaben haben feste Länge. Punktprüfung: nur unkomprimiert (0x04), feste Länge,
auf der Kurve, nicht der Fernpunkt (Kofaktor 1). Es gibt für diese Kombination keinen offiziellen Testvektor; die
App prüft gegen einen eigenen Bekannt-Antwort-Test (tests/vectors/hkem_v3.txt) und rechnet den Kombinierer im Test
unabhängig nach (eigene HKDF-Implementierung).

## Hybride Signatur (TR-02102-1 Abschn. 5.3.4)
```
sig = ECDSA-brainpoolP512r1-SHA3-512(lp(ctx) | data) als r64 | s64   |   ML-DSA-87.Sign(data, ctx) (4627, hedged, pure)
```
Gültig nur, wenn BEIDE gültig sind; 0 < r < q und 0 < s ≤ ⌊q/2⌋ (kanonische Low-s-Form, Befund R8-H3) werden
vor der Prüfung verlangt; beim Signieren wird s > q/2 durch q − s ersetzt. Signaturschlüssel werden nur hierfür
verwendet. ECDSA-Schlüssel: d = (int(SHAKE256(lp("SIGILLUM-v3-ECDSA-expand") | ecdsa_seed32, 96)) mod (q-1)) + 1.

## Modus 6 – Kontakt-Nachricht mit Einmal-Schlüsseln (seit 11.2, R12-N1; gesendet wird nur noch Modus 6)
Wie Modus 4 (unten), aber header[3] = 0x06 und die Ankündigung enthält einen Vorrat von 5 Schlüsseln:
```
ankündigung = seq8 | 0x05 | 5 × (id8 | hkem_pk1697)          (ids verschieden, nie 0^8; jeder Schlüssel geprüft)
Absender:   benutzt die Schlüssel 1–4 der neuesten Ankündigung je GENAU EINMAL, danach Schlüssel 5 (Rückfall) für
            alle weiteren Nachrichten, bis eine neuere Ankündigung des Empfängers eintrifft.
Empfänger:  Schlüssel 1–4 sind Einmal-Schlüssel: nach dem Öffnen sofort gelöscht (zusätzlich alle Schlüssel älterer
            Ankündigungen wie in Modus 4). h3("SIGILLUM-SPENT", header, 16) wird gemerkt, damit eine zweite Kopie als
            „schon geöffnet“ erkannt wird – ihr Inhalt ist nicht mehr lesbar (gewollt).
```
Modus 4 (bis 11.1) wird weiter gelesen und beantwortet (sein einziger Schlüssel gilt als Rückfallschlüssel).
Eigene offene Schlüssel je Kontakt höchstens 1000.

## Modus 4 – Kontakt-Nachricht mit Schlüsselwechsel (bis 11.1)
```
header = "SA" | 0x03 | 0x04 | hkem_ct1697 | nonce12                 (keine Absender-/Empfänger-/Schlüssel-Kennung)
ziel   = neuester vom Empfänger angekündigter Schlüssel (id8, pk) oder sein Basis-Schlüssel (id = 0^8)
key    = HKDF-SHA-512(ikm = K, salt = leer, info = "SIGILLUM-v3-msg" | header[0:4] | empfänger_fp32 | ziel_id8)
ankündigung = seq8 | neue_id8 | neuer_hkem_pk1697
signiert = "SIGILLUM-ARCANUM-v3-sig" | header | empfänger_fp32 | absender_fp32 | ankündigung | inner
klar   = absender_fp32 | hybride Signatur(signiert, ctx = "SIGILLUM-ARCANUM-v3-sig") 4755 | ankündigung | inner
blob   = header | AES-256-GCM-SIV(key, nonce, klar, aad = header)
```
Empfang (Zustand wird nur bei vollem Erfolg und erst nach dem Speichern übernommen):
1. Alle eigenen Schlüssel (Basis + offene Wechselschlüssel aller Kontakte, je Kontakt ≤ 1000) durchprobieren.
2. Absender muss im Kontaktbuch stehen und verifiziert sein; gehört der benutzte Schlüssel zu einem Kontakt,
   muss es genau dieser sein. Beide Signaturen müssen gültig sein; innerer Absender muss passen.
3. Ankündigung übernehmen, wenn `seq` größer als bisher. Neustart des Partners: Nachricht an den Basis-Schlüssel
   mit neuerem Zeitstempel → eigene Wechselschlüssel für ihn löschen. Ältere Basis-Nachricht → Wiederholung, nichts übernehmen.
4. Eigene Wechselschlüssel mit kleinerer `seq` als der benutzte sofort löschen.
5. Lücke in den `seq` des Partners → vor dem Löschen nachfragen; mehrere Nachrichten werden nach `seq` sortiert.
   Die Lücke wird als Anzahl geführt, einzeln genannt werden höchstens 20 Nummern. Gültig: 0 < seq < 2^63.
6. Nachricht schon in "seen" → als Wiederholung melden, nichts übernehmen. Nach einem Neustart (kein Schlüsselstand):
   Nachricht an den Basis-Schlüssel mit Zeitstempel ≤ Untergrenze → Wiederholung. Zeitstempel zählen höchstens
   10 Minuten über die Empfangszeit hinaus.
7. Angekündigte Schlüssel (und Basis-Schlüssel beim Import): ML-KEM-Modulusprüfung und EC-Punktprüfung.

Öffentlicher Schlüssel: `"SAPUB3" | lp(name) | hkem_pk1697 | ecdsa_pk129 | mldsa87_pk2592` (nur kanonisch).
Fingerabdruck: `h3("SIGILLUM-FP-v3", pubbundle, 32)`, angezeigt vollständig (64 Hex-Zeichen).
Namen: 1–64 Zeichen, keine Steuerzeichen, keine Mischung von Schriften; Doppelgänger-Vergleich über eine Skelettform.

## Darstellung
Bytes → 5-Bit-Werte (MSB zuerst). Wert v → Glyph U+E000 + 32·f + v mit zufälliger Form f ∈ {0..3}, oder RFC-4648-Base32.
Beim Einlesen zählen nur exakt diese Zeichen (Base32 auch klein) und Leerraum; alles andere wird abgelehnt.

## Backup
Shamir 2-aus-3 über F_p mit p = 2^521 - 1 (TR-02102-1 Kap. 7), a0 = int(Schlüsseldatei44).
Teil = `"SASHP1" | set_id4 | x | k | n | y66 | h3("SIGILLUM-SHARE-CHK", alles davor, 4)`; strikte Prüfung von
Länge, x, k, n, Satz, y < p. Beide Primzahlen werden im Test per Lucas-Lehmer nachgewiesen.
Wiederherstellen (Befund R8-H4): Jedes Paar wird zusammengesetzt und über Kennung und Prüfsumme der Schlüsseldatei
geprüft. Bei drei Teilen müssen alle auf derselben Geraden liegen; sonst wird das stimmige Paar benutzt und der
abweichende (oder unlesbare) Teil gemeldet. Widersprüchliche Ergebnisse → nichts wird wiederhergestellt.
Bewusst kein offener Hash in den Teilen – ein einzelner Teil bleibt informationstheoretisch ohne Aussage.

## Hand-Modus v2
Körper GF(32) mit x^5 + x^2 + 1. Blatt: Masken m1..m4; je Zeile i: v_i, k_1i..k_4i (alle gleichverteilt, einmalig).
```
p      = [B ÷ 32, B mod 32] | Textwerte | 31-Auffüllung auf Vielfaches von 20       (B = Anzahl Werte nach dem Auffüllen / 10)
c_i    = p_i XOR v_i
t_j    = m_j XOR (k_j1 × p_1) XOR … XOR (k_jn × p_n)        j = 1..4,  × in GF(32)
nachricht = c_1..c_n | t_1..t_4
```
Fälschung ohne Blatt gelingt höchstens mit 32^-4; die Blockzahl im Kopf schützt gegen Kürzen und Verlängern.
Blatt-Nr.: 64 Bit Zufall.
```
blattcode = Base32( sid13 | m1..m4 | (v_i, k_1i..k_4i) je Zeile | prüf10 )
sid13     = Blatt-Nr. als 13 Werte à 5 Bit (65 Bit, oberstes 0)
prüf10    = obere 50 Bit von h3("SIGILLUM-SHEET", alle Werte davor, 8)
```
Beim Einlesen: Prüfsumme, gültige Blattgröße (2 + 10·B Zeilen, B = 2–60) und Übereinstimmung mit der eingetippten
Blatt-Nr. müssen stimmen. Register: Nachrichtenkennung = h3("SIGILLUM-HMSG", Geheimtextwerte, 16).
Die Prüfsumme steht nur im (geheimen) Blattcode, nie in einer Nachricht – die perfekte Geheimhaltung bleibt unberührt.

## Schnell-Entsperren (v11, optional, nur im Arbeitsspeicher)
```
beim Entsperren (nur wenn eingeschaltet): q_salt16 zufällig, Kq = Argon2id("SIGILLUM-ARCANUM-v3\0" | lp("quick") |
                                          lp(NFC(pin).strip()), q_salt16, ops = 4, mem = 2^30)
bei automatischer Sperre:                 versiegelt = nonce12 | AES-256-GCM-SIV(Kq, sitzung_json, aad = "SIGILLUM-v11-quick")
sitzung_json = {name, secret, state, key (A oder null), dkey (A2 oder null), salt, kf, prot}
```
Höchstens 3 PIN-Versuche (wie TR-02102-1 Tab. 6.2, aber nur in der App durchgesetzt), danach verworfen. Verworfen auch bei manuellem Sperren, beim
Schließen und wenn sich die Identitätsdatei seit der Sperre geändert hat (SHA-256 des Dateiinhalts; geprüft VOR dem
Entsiegeln, damit die Meldung nichts über die PIN verrät). Nicht versiegelt wird, solange die Identität mit dem
Notfall-Paket geöffnet ist oder die Erneuerung des Notfall-Codes aussteht. Beim Wiederherstellen werden Schlüssel- und
Salzlängen geprüft (32 bzw. 16 Byte). Wird nie gespeichert.

## Lokale Einstellungen (nicht geheim)
`%APPDATA%\SigillumArcanum\einstellungen.json`: Gerätekennung, gerätespezifische HMAC-Kennungen benutzter
Schlüsseldateien (H1), gedruckter Backups und exportierter Identitäten, Kennungen gesehener gemeinsamer Nachrichten,
Oberfläche (Design, Sperrzeit 5/10/15/30 Minuten, Schnell-Entsperren an/aus, Sprache "de"/"en" seit 11.3), zuletzt benutzte PFADE von
Identitätsdatei und Schlüsseldatei, je Identität (als HMAC-Kennung) die höchste gesehene Schreib-Generation
(11.2, R12-N4: Warnung beim Öffnen einer älteren Fassung). Keine Passphrasen, PINs oder Schlüssel. Ungültige Werte
werden zurückgesetzt (eine ungültige Sprache auf die erkannte Systemsprache).
