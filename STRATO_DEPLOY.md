# Detaillierte Anleitung: Deployment auf Strato Hosting Plus

Diese Anleitung führt dich Schritt für Schritt durch die Installation der Event-Planner-App auf einem Strato Hosting Plus Paket.

## Voraussetzungen prüfen
1.  **Strato-Paket:** Du hast Zugang zum Strato Kunden-Login und dein Paket unterstützt Python (Hosting Plus).
2.  **SFTP & SSH aktivieren:**
    - Logge dich bei Strato ein.
    - Gehe zu **Sicherheit** -> **SFTP-Zugänge einrichten** (bzw. Master-Passwort anlegen).
    - Merke dir den **Benutzernamen** (meist deine Domain, z.B. `wunschname.de`) und das **Master-Passwort**.
3.  **Software am eigenen PC:**
    - Ein FTP-Programm (z.B. **FileZilla**).
    - Ein Terminal (Mac/Linux) oder **PuTTY** (Windows) für den SSH-Zugriff.

---

## 1. Projekt vorbereiten und hochladen

Bevor wir am Server arbeiten, bereiten wir die Dateien vor.

1.  **Dateien hochladen:**
    - Verbinde dich mit FileZilla per SFTP mit deinem Webspace (`Server: ssh.strato.de`, `User: deine-domain.de`, `Passwort: dein-Master-Passwort`).
    - Erstelle im Hauptverzeichnis auf dem Server einen Ordner für dein Projekt, z.B. `/event-planner`.
    - Lade alle Projektdateien (`app/`, `scripts/`, `templates/`, `static/`, `app.py`, `config.py`, `requirements.txt`, `db_schema.sql`) in diesen Ordner hoch.
    - **Wichtig:** Die Datei `.env` mit deinen Passwörtern lädst du **nicht** aus dem Git hoch, sondern erstellst sie gleich manuell auf dem Server, oder lädst eine lokale Kopie hoch, die du **nicht** mit anderen teilst.

2.  **SSH-Verbindung herstellen:**
    - Öffne dein Terminal oder PuTTY.
    - Verbinde dich: `ssh deine-domain.de@ssh.strato.de`
    - Gib dein Master-Passwort ein.

---

## 2. Python-Umgebung einrichten (Auf dem Server)

Wir installieren Python und die Abhängigkeiten direkt auf dem Strato-Server.

1.  **In den Ordner wechseln:**
    ```bash
    cd event-planner
    ```

2.  **Virtuelle Umgebung (venv) erstellen:**
    Dies isoliert deine Installation vom Rest des Servers.
    ```bash
    python3 -m venv venv
    ```

3.  **Abhängigkeiten installieren:**
    Wir aktivieren die Umgebung und installieren die Pakete aus der `requirements.txt`.
    ```bash
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    ```
    *(Falls Fehler auftreten, prüfe, ob `requirements.txt` vorhanden ist. Wenn `mysqlclient` oder `pymysql` Probleme machen, stelle sicher, dass Compiler-Tools verfügbar sind, was bei Managed Hosting oft eingeschränkt ist. Für Strato ist `PyMySQL` (reines Python) oft einfacher als `mysqlclient`.)*

4.  **Konfigurationsdatei (.env) anlegen:**
    Falls noch nicht geschehen, erstelle die Datei:
    ```bash
    nano .env
    ```
    Füge folgenden Inhalt ein (ersetze die Platzhalter mit deinen echten Strato-Datenbank-Daten aus dem Kundenmenü -> "Datenbanken verwalten"):
    ```ini
    FLASK_SECRET_KEY=ein_sehr_langes_zufaelliges_passwort
    SECURITY_PASSWORD_SALT=noch_ein_zufalls_string
    DB_HOST=rdbms.strato.de
    DB_USER=U1234567
    DB_PASSWORD=dein_db_passwort
    DB_NAME=DB1234567
    # Optional für Mails:
    MAIL_SERVER=smtp.strato.de
    MAIL_PORT=587
    MAIL_USE_TLS=true
    MAIL_USERNAME=info@deine-domain.de
    MAIL_PASSWORD=mail_passwort
    MAIL_DEFAULT_SENDER=info@deine-domain.de
    LOGO_URL=
    ```
    Speichern mit `STRG+O`, Beenden mit `STRG+X`.

5.  **Datenbank befüllen:**
    Führe das SQL-Skript aus, um die Tabellen anzulegen.
    ```bash
    mysql -h rdbms.strato.de -u U1234567 -p DB1234567 < db_schema.sql
    ```
    *(Gib das Datenbank-Passwort blind ein, wenn du gefragt wirst.)*

---

## 3. Struktur für CGI/WSGI einrichten

Damit der Apache-Server von Strato weiß, wie er die Python-App starten soll, nutzen wir das CGI-Interface.

1.  **CGI-Ordner anlegen:**
    Erstelle im Projektordner (oder im Hauptverzeichnis `public_html`, je nachdem wo deine Domain hinzeigt) einen Ordner namens `cgi-bin`.
    ```bash
    mkdir cgi-bin
    ```

2.  **Die Start-Datei `app.wsgi` erstellen:**
    Erstelle die Datei `cgi-bin/app.wsgi`:
    ```bash
    nano cgi-bin/app.wsgi
    ```
    Inhalt:
    ```python
    import sys
    import os
    from pathlib import Path

    # 1. Pfad zum Projektverzeichnis (ein Ordner über cgi-bin)
    # Passe dies an, falls deine Struktur anders ist!
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    
    # Füge das Projekt dem Systempfad hinzu
    sys.path.insert(0, str(PROJECT_ROOT))

    # 2. Site-Packages aus dem Virtual Environment hinzufügen
    # Das ist entscheidend bei Strato, damit Flask gefunden wird.
    # Prüfe den genauen Pfad mit 'ls venv/lib/' (z.B. python3.10)
    # Hier nehmen wir an, es ist python3.10:
    venv_site_packages = PROJECT_ROOT / "venv/lib/python3.10/site-packages"
    if venv_site_packages.exists():
        sys.path.insert(0, str(venv_site_packages))
    else:
        # Fallback oder Fehler-Log, falls Python-Version abweicht
        print(f"WARNUNG: Venv Pfad nicht gefunden: {venv_site_packages}", file=sys.stderr)

    # 3. Umgebungsvariablen laden
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / '.env')

    # 4. Flask App importieren
    # 'app' ist der Name der Datei (app.py), 'app' die Variable darin
    from app import app as application
    ```

3.  **Ausführbar machen:**
    Die Datei muss ausführbar sein.
    ```bash
    chmod +x cgi-bin/app.wsgi
    ```

---

## 4. Apache-Konfiguration (.htaccess)

Damit Aufrufe an den Server auch wirklich an Python weitergeleitet werden.

1.  **CGI aktivieren:**
    Erstelle eine Datei `cgi-bin/.htaccess`:
    ```apache
    Options +ExecCGI
    AddHandler cgi-script .cgi .py .wsgi
    ```

2.  **Routing (Pretty URLs) einrichten:**
    Damit deine URL `deinedomain.de/admin` heißt und nicht `deinedomain.de/cgi-bin/app.wsgi/admin`, erstelle eine weitere `.htaccess` Datei **im Hauptordner** (dort, wo der Ordner `cgi-bin` liegt):
    ```bash
    nano .htaccess
    ```
    Inhalt:
    ```apache
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^(.*)$ /cgi-bin/app.wsgi/$1 [L]
    ```

---

## 5. Admin-User initialisieren

Nun erstellen wir den ersten Benutzer, um uns einloggen zu können.

1.  **Python-Shell im Kontext der App öffnen:**
    Stelle sicher, dass du noch im Projektordner bist und das venv aktiviert ist.
    ```bash
    # Falls venv nicht aktiv ist:
    source venv/bin/activate
    
    # Python Konsole starten
    python3
    ```

2.  **Interaktive Befehle eingeben:**
    In der Python-Konsole (`>>>`) folgendes eingeben:

    ```python
    from app import db, AdminUser, Event
    import pyotp
    from werkzeug.security import generate_password_hash
    from app import create_app

    # App Kontext laden (wichtig bei Flask-SQLAlchemy)
    app = create_app()
    ctx = app.app_context()
    ctx.push()

    # 1. Event anlegen
    event = Event(name='Mein Erstes Event', description='Start auf Strato', code_prefix='ST', event_date='2025-06-01 18:00', invitation_text='Willkommen!')
    db.session.add(event)
    db.session.commit()
    print(f"Event erstellt mit ID: {event.id}")

    # 2. Admin anlegen
    secret = pyotp.random_base32()
    # Ersetze 'admin@example.com' und 'DeinPasswort'
    user = AdminUser(email='admin@deine-domain.de', password_hash=generate_password_hash('DeinSicheresPasswort'), totp_secret=secret, role='super_admin')
    db.session.add(user)
    db.session.commit()

    print('------------------------------------------------')
    print('ADMIN ERSTELLT!')
    print(f'Email: admin@deine-domain.de')
    print(f'TOTP Secret (für Google Authenticator): {secret}')
    print('------------------------------------------------')
    
    # Beenden
    exit()
    ```

3.  **WICHTIG:** Kopiere dir das **TOTP Secret** (den Code wie `JBSWY3DPEHPK3PXP...`). Gib diesen Code manuell in deine Authenticator App (Google Auth, Authy, etc.) ein, da wir hier keinen QR-Code anzeigen können. Ohne diesen Code kannst du dich nicht einloggen!

---

## 6. Testen

1.  Öffne deinen Browser: `https://deine-domain.de/admin/login`
2.  Logge dich mit der Email und dem Passwort ein, das du in Schritt 5 festgelegt hast.
3.  Gib den Code aus deiner Authenticator-App ein.
4.  Wenn du das Dashboard siehst: **Herzlichen Glückwunsch!** Deine App läuft.

## Fehlersuche (Troubleshooting)

Falls du einen "Internal Server Error" (Fehler 500) erhältst:
- Prüfe das Error-Log von Strato (oft im Ordner `logs` auf dem FTP).
- Versuche, das Skript manuell in der Konsole zu starten, um Import-Fehler zu finden:
  `python3 cgi-bin/app.wsgi` (Das wird Fehler werfen, weil Umgebungsvariablen fehlen, zeigt aber Syntaxfehler an).
- Prüfe in der `cgi-bin/app.wsgi`, ob der Pfad zu `site-packages` korrekt ist (Python Version beachten, z.B. 3.10 vs 3.11).
