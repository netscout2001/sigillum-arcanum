# Changelog

Each section becomes the text of the GitHub release for that version (`.github/workflows/release.yml`).
Jeder Abschnitt wird zum Text der GitHub-Release dieser Version.

## 11.4

**Stronger passphrase check value / Stärkerer Passphrase-Prüfwert**

* The check value that stops a partner's shared passphrase from being your identity passphrase (`chk.pw`) now uses
  Argon2id (RFC 9106, 3 passes, 64 MiB) instead of HMAC-SHA256 (GitHub code scanning alert #3). It was already stored
  only inside the encrypted identity file.
* Older identities keep working and are converted automatically the next time you enter the passphrase (opening
  without YubiKey, emergency package, or confirming a security change). Messages and contacts are unaffected.
* Fixed: decoding a very large pasted ciphertext took quadratic time and could freeze the app for minutes
  (code scanning alert #7, CWE-407); it is now linear.
* **Note:** once converted, an identity file can no longer be opened with 11.3 or older – update the app on every
  computer where you use this identity.

---

* Der Prüfwert, der verhindert, dass ein Partner deine Identitäts-Passphrase bekommt (`chk.pw`), nutzt jetzt Argon2id
  statt HMAC-SHA256. Ältere Identitäten werden beim nächsten Eingeben der Passphrase automatisch umgestellt.
* **Hinweis:** Eine umgestellte Identitätsdatei öffnet sich nicht mehr mit 11.3 oder älter – die App auf jedem
  Rechner aktualisieren, auf dem du diese Identität benutzt.

## 11.3

**English and German / Deutsch und Englisch**

* The app speaks English and German. On first start it follows the Windows display language (German → German,
  anything else → English); switch under “Keys & security” → “Sprache / Language”.
* Messages, printed PDFs and suggested file names follow the chosen language.
* Cryptography, file formats and stored data are unchanged – 11.2 identities and messages keep working, also between
  an English and a German app.
* New English manual [`MANUAL.md`](MANUAL.md) with English screenshots and English format specification [`FORMAT.en.md`](FORMAT.en.md).

---

* Die App spricht Deutsch und Englisch. Beim ersten Start folgt sie der Windows-Anzeigesprache (Deutsch → Deutsch,
  sonst Englisch); umschalten unter „Schlüssel & Sicherheit“ → „Sprache / Language“.
* Meldungen, gedruckte PDFs und vorgeschlagene Dateinamen folgen der gewählten Sprache.
* Kryptografie, Dateiformate und gespeicherte Daten unverändert.

## 11.2

First public version / Erste öffentliche Version.

* One-time keys per message (pool of 5 receive keys), stricter passphrase and PIN rules, cloud passkeys rejected,
  rollback warning for restored identity files, clipboard clearing, foreign known-answer vectors in the self-test.
* Einmal-Schlüssel je Nachricht, strengere Passphrase- und PIN-Regeln, Cloud-Passkeys abgelehnt, Warnung bei älterer
  Identitätsdatei, Zwischenablage, Fremd-Prüfwerte im Selbsttest.
