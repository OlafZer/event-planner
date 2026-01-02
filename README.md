# Event Planner (Multi-Tenant Flask Blueprint)

Diese Dokumentation liefert einen vollständigen, sicherheitsorientierten Entwurf für eine mandantenfähige Event-Anmelde-Anwendung auf Basis von Flask, SQLAlchemy und MariaDB, ausgelegt für Strato Hosting Plus.

## Projektstruktur

- `app.py`: Einstiegspunkt mit Flask-App, Modellen, Rollen-Checks, 2FA-Login und Beispiel-Routen.
- `db_schema.sql`: SQL-Skript zur Erstellung der mandantenfähigen Tabellen (Events, Admins, Gästeliste pro Event, Zugriffs-Logs).
- `.env.example`: Vorlage für Umgebungsvariablen (niemals im Klartext produktive Secrets speichern).
- `readme`: Historische Notiz aus dem Ausgangsrepository.
- `DEPLOYMENT.md`: Schritt-für-Schritt-Anleitung für Strato Hosting Plus inklusive WSGI/CGI-Pfaden.

## Wichtige Design-Prinzipien

- **Strikte Mandantentrennung:** Jede Abfrage enthält konsequent einen `event_id`-Filter, sodass Event-Admins keine fremden Daten sehen können.
- **Feste Status-Optionen:** Die Status-Werte sind zentral definiert und identisch für alle Events.
- **2FA-Pflicht:** Alle Admin-Routen verlangen ein TOTP-basiertes Zwei-Faktor-Login.
- **CSRF-Schutz & Validierung:** Formulare nutzen CSRF-Token und Regex-Validierung, um XSS und Request-Forgery zu verhindern.
- **Konfigurierbarkeit über Umgebungsvariablen:** Datenbank- und Mail-Zugänge werden ausschließlich aus `.env` gelesen.

## CSV-Import-Format

Die Import-Logik erwartet eine pro Event getrennte CSV-Datei mit genau diesen Spalten in der Reihenfolge:

```
name,nachname,kategorie,max_persons,invite_code,email,telephone,notify_admin
```

- `name`: Pflichtfeld für den Vornamen.
- `nachname`: Optionaler Nachname.
- `kategorie`: Eine der erlaubten Kategorien aus der Anwendung (Familie, Nachbarn, Freunde, Arbeit Birgit, Arbeit Olaf, Volleyball, Toastmasters).
- `max_persons`: Ganzzahlige maximale Personenzahl für diese Einladung.
- `invite_code`: Achtstelliger, eindeutig pro Event gültiger Code (z. B. `AB12CD34`).
- `email`: Optionale Kontaktadresse.
- `telephone`: Optionale Telefonnummer.
- `notify_admin`: `true` oder `false`, ob der zuständige Event-Admin bei Statusänderungen per E-Mail informiert wird.

Jeder Datensatz wird im Import-Prozess strikt mit der jeweiligen `event_id` verknüpft, sodass keine Fremddaten überschrieben werden können.

## Deployment-Übersicht

Eine Schritt-für-Schritt-Anleitung für Strato Hosting Plus findet sich in `DEPLOYMENT.md`. Dort sind auch Hinweise zu WSGI/CGI-Pfaden enthalten.

## Musikwünsche aktivieren

Die Anwendung unterstützt optionale Musikwünsche pro Event. Für bestehende Datenbanken führe zuerst die Migration aus:

```
mysql -h <host> -u <user> -p <database> < db_migration_music_requests.sql
```

- Neu: Spalte `music_requests_enabled` in `events`, Tabelle `music_requests` für die Wünsche (mit Gast- und Event-IDs).
- Admins können die Funktion im Dashboard über **🎵 Musikwünsche verwalten** pro Event ein- oder ausschalten, Wünsche einsehen oder als CSV exportieren.
- Gäste finden bei aktivierten Events auf ihrer Einladung einen Button, um eigene Wünsche anzulegen oder zu löschen.
