# Deployment auf Strato Hosting Plus

Diese Anleitung beschreibt die wesentlichen Schritte, um die Flask-Anwendung im Strato Hosting Plus Umfeld mit Python- und MariaDB-Unterstützung sicher zu betreiben.

## Voraussetzungen
- Aktiver Strato Hosting Plus Tarif mit Shell-Zugang und aktiviertem Python-Support.
- MariaDB-Datenbankzugang (Host, Port, Benutzer, Passwort, Datenbankname) bekannt.
- Lokale `.env` Datei mit allen Secrets vorbereitet (nicht ins Repository einchecken).

## Schritte

1. **Repository bereitstellen**
   - Projektinhalt per Git oder SFTP nach `/home/<user>/` übertragen, z. B. nach `/home/<user>/event-planner/`.

2. **Virtuelle Umgebung einrichten**
   - `python3 -m venv venv` ausführen.
   - `source venv/bin/activate` laden.
   - Abhängigkeiten installieren: `pip install -r requirements.txt` (Datei bei Bedarf erzeugen, z. B. mit Flask, SQLAlchemy, PyOTP, Flask-WTF, python-dotenv, email-sender-Bibliothek).

3. **Environment konfigurieren**
   - `.env` aus `.env.example` ableiten und mit realen Werten füllen.
   - Sicherstellen, dass die Datei nur für den Account lesbar ist (`chmod 600 .env`).

4. **WSGI vorbereiten**
   - Strato verlangt eine WSGI-Datei, z. B. unter `~/event-planner/app.wsgi`:
     ```python
     import sys
     import os

     from pathlib import Path
     from dotenv import load_dotenv

     # Arbeitsverzeichnis setzen
     project_root = Path(__file__).resolve().parent
     sys.path.insert(0, str(project_root))

     # Umgebungsvariablen laden
     load_dotenv(project_root / ".env")

     # Flask-App importieren
     from app import app as application
     ```
   - In der Strato-Konfiguration den WSGI-Pfad auf diese Datei setzen.

5. **CGI-/FCGI-Kompatibilität**
   - Falls FCGI erwartet wird, kann ein Wrapper-Skript genutzt werden, das auf die WSGI-App verweist (z. B. `fastcgi.py`), analog zu Strato-Dokumentation.

6. **Datenbank migrieren**
   - Mit `mysql -h <host> -u <user> -p <database> < db_schema.sql` die Tabellen erzeugen.

7. **Start und Test**
   - Über Strato WSGI wird die App automatisch geladen. Für lokale Tests `flask --app app run --debug` nutzen (nicht in Produktion).

8. **Sicherheitshärtung**
   - Debug-Modus in Produktion deaktivieren.
   - HTTPS über Strato-Zertifikat erzwingen.
   - Regelmäßige Rotation von TOTP-Secret und Admin-Passwörtern einplanen.
