# Changelog

Each section becomes the text of the GitHub release for that version (`.github/workflows/release.yml`).
Jeder Abschnitt wird zum Text der GitHub-Release dieser Version.

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
