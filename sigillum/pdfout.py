"""Druckvorlagen als PDF: Zufallsblätter, Referenzkarte, Geheimtext, Backup-Teile."""
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from . import handmode
from .codec import PUA_BASE

HERE = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = os.path.join(HERE, "fonts")
_registered = False


def _fonts():
    global _registered
    if not _registered:
        pdfmetrics.registerFont(TTFont("Sigillum", os.path.join(FONT_DIR, "SigillumArcanum-Bold.ttf")))
        pdfmetrics.registerFont(TTFont("SigillumThin", os.path.join(FONT_DIR, "SigillumArcanum-Regular.ttf")))
        _registered = True


W, H = A4
M = 15 * mm


def _title(c, text, sub=None):
    c.setFont("Helvetica-Bold", 15)
    c.drawString(M, H - M - 5 * mm, text)
    if sub:
        c.setFont("Helvetica", 9)
        c.drawString(M, H - M - 11 * mm, sub)


def pad_sheets(path, sheet: "handmode.Sheet"):
    """Zwei identische Exemplare (Absender / Empfänger). Je Zeile: V (Verschlüsselung), P1–P4 (Prüfschlüssel)."""
    _fonts()
    c = canvas.Canvas(path, pagesize=A4)
    rows, rh = sheet.rows, 5.0 * mm
    top = H - M - 30 * mm
    per_col = int((top - M - 12 * mm) // rh)
    head = ["Zeile", "V", "P1", "P2", "P3", "P4"]
    widths = [13 * mm, 13 * mm, 11 * mm, 11 * mm, 11 * mm, 11 * mm]

    def table_head(x, y):
        c.setFont("Helvetica-Bold", 8)
        xx = x
        for t, w in zip(head, widths):
            c.drawString(xx, y, t)
            xx += w

    for copy in ("Exemplar Absender", "Exemplar Empfänger"):
        i = 0
        page = 1
        while i < len(rows) or page == 1:
            _title(c, f"Sigillum Arcanum – Zufallsblatt Nr. {sheet.id}",
                   f"{copy} · Seite {page} · {len(rows)} Zeilen · erstellt {datetime.now():%d.%m.%Y} · "
                   "NUR EINMAL VERWENDEN · danach vernichten")
            if page == 1:
                c.setFont("Helvetica-Bold", 10)
                c.drawString(M, H - M - 19 * mm, "Masken  M1  M2  M3  M4:")
                c.setFont("Courier-Bold", 11)
                c.drawString(M + 48 * mm, H - M - 19 * mm, "   ".join(f"{m:2d}" for m in sheet.masks))
                c.setFont("Helvetica", 8)
                c.drawString(M + 95 * mm, H - M - 19 * mm, "* Zeilen 1 und 2 verschlüsseln die Blockzahl.")
            for col in range(2):
                x0 = M + col * 92 * mm
                table_head(x0, top + 2 * mm)
                y = top - rh
                for _ in range(per_col):
                    if i >= len(rows):
                        break
                    if i % 2 == 0:
                        c.setFillGray(0.93)
                        c.rect(x0 - 1 * mm, y - 1.4 * mm, sum(widths), rh, stroke=0, fill=1)
                        c.setFillGray(0)
                    c.setFont("Helvetica", 8)
                    c.drawString(x0, y, f"{i + 1:>3}" + ("*" if i < 2 else ""))
                    c.setFont("Courier-Bold", 10)
                    xx = x0 + widths[0]
                    for v, w in zip(rows[i], widths[1:]):
                        c.drawString(xx, y, f"{v:2d}")
                        xx += w
                    y -= rh
                    i += 1
            c.setFont("Helvetica", 7)
            c.drawString(M, M, "Geheimwert = Klartext XOR V.  Prüfwert S_j = M_j XOR (P_j × Klartext) über alle Zeilen. "
                               "Tafeln und Ablauf: Referenzkarte.")
            c.showPage()
            page += 1
        # Blattcode für die Rechenhilfe der App
        _title(c, f"Blattcode Nr. {sheet.id}", f"{copy} · Nur für die Rechenhilfe der App · genauso geheim wie das Blatt")
        c.setFont("Courier-Bold", 9.5)
        groups = sheet.code().split(" ")
        y = H - M - 22 * mm
        for k in range(0, len(groups), 12):
            if y < M + 5 * mm:
                c.showPage()
                y = H - M - 10 * mm
                c.setFont("Courier-Bold", 9.5)
            c.drawString(M, y, " ".join(groups[k:k + 12]))
            y -= 5 * mm
        c.showPage()
    c.save()


def _grid(c, title, sub, fn):
    _title(c, title, sub)
    cell = 5.4 * mm
    ox, oy = M + 6 * mm, H - M - 22 * mm
    c.setFont("Helvetica-Bold", 6.5)
    for i in range(32):
        c.drawCentredString(ox + (i + 0.5) * cell, oy + 1.5 * mm, str(i))
        c.drawRightString(ox - 1 * mm, oy - (i + 0.7) * cell, str(i))
    c.setFont("Helvetica", 6.5)
    for r in range(32):
        for s in range(32):
            if (r // 4 + s // 4) % 2 == 0:
                c.setFillGray(0.92)
                c.rect(ox + s * cell, oy - (r + 1) * cell, cell, cell, stroke=0, fill=1)
            c.setFillGray(0)
            c.drawCentredString(ox + (s + 0.5) * cell, oy - (r + 0.7) * cell, str(fn(r, s)))
    c.showPage()


def reference_card(path):
    _fonts()
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, "Sigillum Arcanum – Referenzkarte Hand-Modus",
           "Wert · Buchstabe · Ziffern-Modus · vier gleichwertige Glyphen-Formen")
    letters = [chr(65 + i) for i in range(26)] + ["Leer", ".", ",", "Umsch.", "Satz", "Füll"]
    y0 = H - M - 22 * mm
    for v in range(32):
        col, row = divmod(v, 16)
        x = M + col * 92 * mm
        y = y0 - row * 11 * mm
        c.setFont("Helvetica-Bold", 10)
        c.drawString(x, y, f"{v:2d}")
        c.setFont("Helvetica", 10)
        c.drawString(x + 8 * mm, y, letters[v])
        c.drawString(x + 22 * mm, y, str(v) if v < 10 else "")
        c.setFont("Sigillum", 22)
        for k in range(4):
            c.drawString(x + 32 * mm + k * 13 * mm, y - 2 * mm, chr(PUA_BASE + 32 * k + v))
    y = y0 - 16 * 11 * mm - 2 * mm
    lines = [
        ("Klartext:", "Werte laut Tabelle. Ziffern: 29 schaltet um und zurück. Satzzeichen: 30, dann 0 ?  1 !  2 :  3 -"
                      "  4 (  5 )  6 \".  ä=ae, ö=oe, ü=ue, ß=ss."),
        ("Auffüllen:", "Mit 31 auf ein Vielfaches von 20 Werten. Blockzahl B = Anzahl / 10. Davor zwei Werte: B÷32 und B mod 32."),
        ("Verschlüsseln:", "Zeile für Zeile Geheimwert = Klartextwert XOR V (XOR-Tafel). Zeile 1 und 2 sind die Blockzahl."),
        ("Prüfwerte:", "S1–S4 starten mit M1–M4. Je Zeile: S_j = S_j XOR (P_j × Klartextwert). × immer aus der Mal-Tafel!"),
        ("", "Die vier Endwerte S1–S4 hinten an den Geheimtext anhängen."),
        ("Entschlüsseln:", "Klartextwert = Geheimwert XOR V. Dann S1–S4 genauso berechnen und mit den letzten vier Werten vergleichen."),
        ("", "Weicht auch nur einer ab: Nachricht verwerfen (verändert oder falsch abgeschrieben)."),
        ("Schreiben:", "Jeden Geheimwert als beliebige der vier Glyphen-Formen – Formen abwechseln."),
        ("Sicherheit:", "Jedes Blatt nur EINMAL. Unbemerkte Fälschung gelingt nur mit 1 : 1.048.576 – auch mit KI oder Quantencomputer."),
    ]
    for k, t in lines:
        c.setFont("Helvetica-Bold", 8.5)
        c.drawString(M, y, k)
        c.setFont("Helvetica", 8.5)
        c.drawString(M + 24 * mm, y, t)
        y -= 4.8 * mm
    c.showPage()
    _grid(c, "XOR-Tafel: Zeile XOR Spalte", "Zum Ver- und Entschlüsseln und zum Aufsummieren der Prüfwerte. "
          "Gilt in beide Richtungen: (a XOR b) XOR b = a.", lambda r, s: r ^ s)
    _grid(c, "Mal-Tafel: Zeile × Spalte  (Körper GF(32), Polynom x^5 + x^2 + 1)",
          "Für die Prüfwerte: P_j (Zeile) × Klartextwert (Spalte). Nicht normal multiplizieren – nur diese Tafel!", handmode.gf_mul)
    c.save()


def cipher_text(path, glyph_text: str, title="Sigillum Arcanum – Nachricht"):
    _fonts()
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, title)
    y = H - M - 20 * mm
    size = 15
    for line in glyph_text.splitlines():
        for chunk in [line[i:i + 30] for i in range(0, len(line), 30)]:
            if y < M:
                c.showPage()
                y = H - M
            c.setFont("Sigillum", size)
            c.drawString(M, y, chunk)
            y -= 9 * mm
    c.showPage()
    c.save()


def share_sheet(path, share_text: str, idx: int, n: int, k: int):
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, f"Sigillum Arcanum – Backup-Teil {idx} von {n}",
           f"Zum Wiederherstellen werden {k} beliebige Teile benötigt. Einzelne Teile verraten nichts.")
    y = H - M - 25 * mm
    c.setFont("Courier-Bold", 12)
    for line in share_text.splitlines():
        c.drawString(M, y, line)
        y -= 7 * mm
    c.setFont("Helvetica", 9)
    c.drawString(M, y - 6 * mm, "Getrennt von den anderen Teilen aufbewahren (z. B. Zuhause / Schließfach / Vertrauensperson).")
    c.showPage()
    c.save()


def package_sheet(path, share_text: str, idx: int, n: int, k: int, tag: str):
    """Ein Teil des Notfall-Pakets (Identitäts-Schlüsseldatei + Notfall-Code, Shamir k aus n)."""
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, f"Sigillum Arcanum – NOTFALL-PAKET {tag} · Teil {idx} von {n}",
           f"Erstellt {datetime.now():%d.%m.%Y}. {k} beliebige Teile + Passphrase + PIN öffnen die Identität OHNE YubiKey.")
    y = H - M - 25 * mm
    c.setFont("Courier-Bold", 12)
    for line in share_text.splitlines():
        c.drawString(M, y, line)
        y -= 7 * mm
    y -= 6 * mm
    c.setFont("Helvetica-Bold", 9.5)
    for line in ("Diesen Teil an einem EIGENEN Ort aufbewahren – getrennt von den anderen Teilen.",
                 "NIE zusammen mit Passphrase oder PIN der Identität aufbewahren.",
                 "Ein einzelner Teil verrät nichts. Nach dem Drucken die PDF-Datei löschen.",
                 "Wird ein neues Notfall-Paket erzeugt, ist dieses ungültig: dann vernichten."):
        c.drawString(M, y, line)
        y -= 5.5 * mm
    c.setFont("Helvetica", 9)
    y -= 3 * mm
    for line in ("Notfall: App öffnen, oben rechts Identitätsdatei, Passphrase und PIN eintragen, dann „Notfall…“ wählen und",
                 f"{k} Teile einfügen. Danach verlangt die App sofort ein neues Notfall-Paket."):
        c.drawString(M, y, line)
        y -= 5 * mm
    c.showPage()
    c.save()


def _lines(c, y, lines, font="Helvetica", size=10, step=5.5 * mm):
    c.setFont(font, size)
    for line in lines:
        c.drawString(M, y, line)
        y -= step
    return y


def fingerprint_card(path, name: str, fingerprint: str):
    """v11: Karte zum Verifizieren – enthält nur Öffentliches (Name + Fingerabdruck)."""
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, "Sigillum Arcanum – Fingerabdruck-Karte",
           f"Erstellt {datetime.now():%d.%m.%Y}. Nicht geheim – darf gezeigt und vorgelesen werden.")
    y = H - M - 30 * mm
    c.setFont("Helvetica-Bold", 13)
    c.drawString(M, y, name)
    y -= 12 * mm
    groups = fingerprint.split()
    c.setFont("Courier-Bold", 18)
    for i in range(0, len(groups), 4):
        c.drawString(M, y, "  ".join(groups[i:i + 4]))
        y -= 10 * mm
    y -= 4 * mm
    _lines(c, y, ["So verifiziert dein Kontakt dich: persönlich oder per Video mit Rückfrage treffen,",
                  "die 16 Gruppen vorlesen, der Kontakt tippt sie in „Verifizieren…“ vollständig ein.",
                  "Ein normaler Telefonanruf reicht nicht – Stimmen lassen sich mit KI fälschen."], size=10)
    c.showPage()
    c.save()


def partner_sheet(path, partner: str, passphrase: str, pin: str, tag: str):
    """v11: Übergabeblatt für einen gemeinsamen Schlüssel (Passphrase + PIN). Die Schlüsseldatei liegt auf dem
    USB-Stick des Partners. Nur zum Drucken – die App löscht die PDF-Datei danach."""
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, f"Sigillum Arcanum – Gemeinsamer Schlüssel mit {partner} · {tag}",
           f"Erstellt {datetime.now():%d.%m.%Y}. GEHEIM – nur persönlich übergeben.")
    y = H - M - 30 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(M, y, "Passphrase (7 Wörter):")
    y -= 9 * mm
    c.setFont("Courier-Bold", 15)
    words = passphrase.split()
    for i in range(0, len(words), 4):
        c.drawString(M, y, "  ".join(words[i:i + 4]))
        y -= 8 * mm
    y -= 4 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(M, y, "PIN:")
    c.setFont("Courier-Bold", 15)
    c.drawString(M + 15 * mm, y, pin)
    y -= 14 * mm
    _lines(c, y, ["Dazu gehört die Schlüsseldatei auf dem USB-Stick. Ohne alle drei Teile lässt sich nichts öffnen.",
                  "Empfänger: In der App unter „Kontakte & Partner“ > „Vorhandenen übernehmen…“ eintragen.",
                  "Danach dieses Blatt vernichten oder getrennt vom USB-Stick verschlossen aufbewahren.",
                  "Für regelmäßigen Austausch sind Kontakt-Nachrichten sicherer (Einmal-Schlüssel je Nachricht)."],
           size=9.5)
    c.showPage()
    c.save()


def quick_guide(path):
    """v11: Kurzanleitung (1 Seite, ohne Geheimnisse) zum Aufbewahren neben dem Notfall-Paket."""
    c = canvas.Canvas(path, pagesize=A4)
    _title(c, "Sigillum Arcanum 11 – Kurzanleitung", "Enthält keine Geheimnisse. Neben dem Notfall-Paket aufbewahren.")
    y = H - M - 26 * mm
    sections = [
        ("Was liegt wo?", ["Passphrase: auf Papier, verschlossen – im Alltag mit YubiKey nicht nötig.",
                           "Schlüsseldatei der Identität: USB-Stick. Nie in OneDrive/Dropbox, nie neben der Identitätsdatei.",
                           "Identitätsdatei: lokaler Ordner (nicht synchronisiert).",
                           "Backup-Teile und Notfall-Paket: 3 Papiere an 3 getrennten Orten, nie bei der Passphrase."]),
        ("Alltag", ["Start: Identitätsdatei, PIN, Schlüsseldatei; mit YubiKey: FIDO-PIN + Antippen.",
                    "Ohne YubiKey zusätzlich die Passphrase. Ohne Bedienung sperrt die App nach der eingestellten Zeit (Standard 10 Min.)."]),
        ("Schreiben / Lesen", ["Kontakt-Nachricht (empfohlen) oder Partner mit gemeinsamem Schlüssel wählen.",
                               "Mehrere Nachrichten beim Lesen durch Leerzeilen trennen – die App sortiert sie."]),
        ("Neuer Kontakt", ["Öffentliche Schlüssel tauschen, dann persönlich oder per Video den Fingerabdruck",
                           "vorlesen lassen und vollständig eintippen. Telefon reicht nicht (KI-Stimmen)."]),
        ("Notfall (YubiKey weg/defekt)", ["Start > „Notfall…“ > 2 Teile des Notfall-Pakets + Passphrase + PIN.",
                                          "Danach verlangt die App sofort ein neues Paket; alte Papiere vernichten."]),
        ("Schlüsseldatei verloren", ["Tab „Backup“ > 2 (besser 3) Teile eingeben > neue Schlüsseldatei speichern."]),
    ]
    for head, lines in sections:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(M, y, head)
        y -= 6 * mm
        y = _lines(c, y, ["• " + x for x in lines], size=9.5, step=5 * mm) - 3 * mm
    c.showPage()
    c.save()
