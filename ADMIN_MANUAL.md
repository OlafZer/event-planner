# Admin-Story: Einladungen vorbereiten und verschicken

Diese Anleitung beschreibt, wie du als Admin ein Event anlegst, Gäste importierst und Einladungen verteilst.

1. **Anmelden**
   - Öffne `/admin/login`, melde dich mit E-Mail und Passwort an und gib danach deinen TOTP-Code ein.

2. **Neues Event anlegen**
   - Öffne das Dashboard und fülle das Formular „Neues Event anlegen“ aus:
     - *Event-Name* und *Beschreibung* nach Bedarf.
     - *Event-Datum* im Format `JJJJ-MM-TT hh:mm` (HTML `datetime-local`).
     - *Einladungstext*: Dieser Text erscheint auf der Gäste-Seite, in der E-Mail und im PDF.
     - *Hintergrundbild-URL* (optional): Eine voll auflösbare Bild-URL, z. B. `https://source.unsplash.com/featured/?party`. Das Bild wird als ganzseitiger Hintergrund eingebunden (cover, center). Nutze helle, hochauflösende Motive, damit Text gut lesbar bleibt. Bewährt haben sich 1920x1080 px oder größer.

3. **Logo einbinden**
   - Lege ein Logo unter `static/logo.png` ab **oder** setze die Umgebungsvariable `LOGO_URL` auf eine externe Bild-URL (PNG/SVG, transparente Hintergründe sind ideal). Empfohlene Größe: ca. 200x60 px. Das Logo erscheint oben links in der Navigation.

4. **Gäste importieren**
   - Wähle dein Event in der Event-Auswahl.
   - Lade eine CSV mit **genau** den Spalten `name,nachname,kategorie,max_persons,invite_code,email,telephone,notify_admin` hoch (keine zusätzlichen Spalten).
   - CSV-Format:
     - **Trennzeichen:** Komma (`,`).
     - **Encoding:** UTF-8.
     - **Header-Reihenfolge:** beliebig, aber die Namen müssen exakt stimmen.
   - Kategorien müssen zu den erlaubten Werten passen (Familie, Nachbarn, Freunde, Arbeit Birgit, Arbeit Olaf, Volleyball, Toastmasters).
   - `notify_admin` kann `true/false`, `1/0`, `yes/no` oder `ja/nein` sein und steuert, ob du bei Status-Änderungen per E-Mail informiert wirst.
   - **Beispielzeilen:** Die heruntergeladene CSV enthält eine Musterzeile (Max Mustermann). Ersetze diese Zeile durch echte Gäste oder füge weitere Zeilen darunter hinzu.
   - **Invite-Code:** Muss aus dem Event-Prefix + 6 Zeichen bestehen (z. B. `ABABCDEF`). Doppelte Codes werden übersprungen.
   - **Fehlerhinweis:** Nicht passende Kategorien, ungültige E-Mails oder fehlerhafte Codes werden pro Zeile übersprungen und als Hinweis im Admin-Dashboard angezeigt.

5. **Gäste manuell hinzufügen**
   - Nutze das Formular „Gast manuell anlegen“ für Einzel-Imports. Du gibst den Klartext-Invite-Code ein; die App speichert davon nur den Hash.

6. **Einladungen versenden**
   - In der Gästeliste findest du pro Gast Aktionen:
     - **E-Mail senden** (nur, wenn eine Adresse hinterlegt ist): Verschickt den Einladungstext, einen Link und das PDF als Anhang.
     - **Text kopieren**: Kopiert einen fertigen Messenger-Text mit dem persönlichen Link in die Zwischenablage.
     - **PDF laden**: Lädt das A6-PDF mit QR-Code herunter, das du ausdrucken oder weiterleiten kannst.

7. **Status-Updates**
   - Gäste melden sich über ihre Invite-URL an. Wenn `notify_admin` aktiv ist, erhältst du bei Statusänderungen eine Info-Mail mit Personenanzahl.

8. **Demo-Daten**
   - Für lokale Tests: `python scripts/create_demo_data.py` (vorher `.env` und DB verbinden). Es werden Events „Sommerfest“ und „Weihnachtsfeier“ plus 15 Gäste je Event angelegt.

9. **Musikwünsche sammeln**
   - Führe für bestehende Datenbanken das Skript `db_migration_music_requests.sql` aus (siehe README).
   - Öffne im Dashboard das gewünschte Event und klicke auf **🎵 Musikwünsche verwalten**.
   - Aktiviere die Funktion per Schalter. Gäste sehen dann auf ihrer Einladung einen Button „Musikwünsche eingeben“.
   - Auf der Admin-Seite kannst du Wünsche einsehen, löschen oder als CSV exportieren (inkl. eindeutiger Gast-ID).

## Hinweise zu Bildern
- **Hintergrund**: Verwende lizenzfreie Fotos, ideal im Querformat. Die Datei sollte eine öffentliche URL sein (HTTPS), damit Browser sie ohne Auth laden können.
- **Logo**: Nutze PNG oder SVG mit transparentem Hintergrund. Halte die Dateigröße klein (<200 kB), damit Seiten schnell laden.
