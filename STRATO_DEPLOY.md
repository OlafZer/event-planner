# Deployment auf Strato Hosting Plus

1. **Projekt vorbereiten**
   - Lokales Python-Umfeld mit Python 3.10+ nutzen und Abhängigkeiten via `pip install -r requirements.txt` installieren.
   - `.env` Datei mit `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `FLASK_SECRET_KEY`, optional SMTP-Zugangsdaten für Benachrichtigungen im Projektstamm anlegen (nicht committen).
   - MariaDB-Schema mit `mysql -u <user> -p <dbname> < db_schema.sql` aufspielen (erstellt Events, Admins, Gäste, Logs).

2. **Struktur für CGI/WSGI**
   - Im Strato Hosting Plus einen Ordner `cgi-bin` nutzen und darin eine WSGI-Bridge z.B. `app.wsgi` ablegen.
   - Beispiel `app.wsgi` Inhalt:

```python
import sys, os
from pathlib import Path

# Pfade setzen, damit das Projekt gefunden wird
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Umgebungsvariablen aus .env laden
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / '.env')

from app import app as application  # Flask-App importieren
```

3. **Apache-Konfiguration**
   - In Strato Hosting Plus erfolgt WSGI über `.htaccess` im `cgi-bin` Verzeichnis:

```
Options +ExecCGI
AddHandler cgi-script .cgi .py .wsgi
```

4. **Static & Templates**
   - `templates/` und `static/` Ordner ins gleiche Verzeichnis wie `app.py` kopieren.
   - Sicherstellen, dass `application` im WSGI-Skript auf die App zeigt.

5. **Sicherheit aktivieren**
   - `FLASK_SECRET_KEY` und DB-Zugangsdaten ausschließlich in `.env` hinterlegen.
   - `pip install flask flask_sqlalchemy flask_login flask_wtf pyotp python-dotenv pymysql` im Ziel ausführen.
   - Optional `export FLASK_ENV=production` setzen, um Debug zu deaktivieren.

6. **Admin-User initialisieren**
   - Interaktives Python im Server starten (Super-Admin legt Events an, Event-Admins sind event-gebunden):

```python
from app import db, AdminUser, Event
import pyotp
from werkzeug.security import generate_password_hash
from app import app

with app.app_context():
    event = Event(name='Sommerfest 2025', description='Mandantenfähiges Beispiel')
    db.session.add(event)
    db.session.commit()
    secret = pyotp.random_base32()
    user = AdminUser(email='admin@example.com', password_hash=generate_password_hash('STRONGPASS!'), totp_secret=secret, role='super_admin')
    db.session.add(user)
    db.session.commit()
    print('TOTP Secret:', secret)
```

7. **Testen**
   - `/admin/login` aufrufen, mit Passwort anmelden, anschließend den TOTP-Code aus der Authenticator-App eingeben.
   - Events anlegen, Event-Admins binden und Einladungslinks als `/event/<event_id>/invite/<code>` testen; CSV-Import im Admin-Dashboard nutzen.
