# Deployment auf Strato Hosting Plus

Diese Anleitung führt dich Schritt für Schritt durch die Installation der Event-Planner-App auf einem Strato Hosting Plus Paket.

## Voraussetzungen prüfen
1.  **Strato-Paket:** Du hast Zugang zum Strato Kunden-Login und dein Paket unterstützt Python (Hosting Plus).
2.  **SFTP & SSH aktivieren:**
    - Logge dich bei Strato ein.
    - Gehe zu **Sicherheit** -> **SFTP-Zugänge einrichten** (bzw. Master-Passwort anlegen).
    - Merke dir den **Benutzernamen** (meist deine Domain, z.B. `wunschname.de`) und das **Master-Passwort**.
3.  **GitHub-Repository:** Dein Code liegt auf GitHub bereit.
4.  **Software am eigenen PC:**
    - Ein Terminal (Mac/Linux) oder **PuTTY** (Windows) für den SSH-Zugriff.

---

## 1. Verbindung herstellen und Code abrufen

Wir arbeiten direkt auf dem Server via SSH.

1.  **SSH-Verbindung herstellen:**
    Öffne dein Terminal und verbinde dich:
    ```bash
    ssh deine-domain.de@ssh.strato.de
    # Gib dein Master-Passwort ein
    ```

2.  **Zielordner vorbereiten:**
    Wechsele in das Verzeichnis, auf das deine (Sub-)Domain zeigen soll (z. B. `~/einladung`).
    ```bash
    # Beispiel: Verzeichnis erstellen falls nötig
    mkdir einladung
    cd einladung
    ```

3.  **GitHub-Authentifizierung (SSH-Key) einrichten:**
    Damit der Server den Code von GitHub laden darf, benötigt er einen eigenen SSH-Schlüssel.
    
    * **Schlüssel erzeugen:**
        ```bash
        # Ordner erstellen und Rechte setzen
        mkdir -p ~/.ssh && chmod 700 ~/.ssh
        
        # Schlüssel generieren (immer Enter drücken für Standardnamen 'id_ed25519')
        ssh-keygen -t ed25519 -C "strato-server"
        ```
    
    * **Public Key anzeigen & kopieren:**
        ```bash
        cat ~/.ssh/id_ed25519.pub
        ```
        Kopiere die Ausgabe (beginnt mit `ssh-ed25519`).
    
    * **Bei GitHub hinterlegen:**
        Gehe auf GitHub zu **Settings** -> **SSH and GPG keys** -> **New SSH key** und füge den kopierten Key ein.
    
    * **Verbindung testen:**
        ```bash
        ssh -T git@github.com
        # Bestätige den Fingerprint mit 'yes'
        # Erwartete Ausgabe: "Hi <User>! You've successfully authenticated..."
        ```

4.  **Projekt klonen:**
    Lade die Dateien direkt in das aktuelle Verzeichnis (beachte den Punkt am Ende!).
    ```bash
    git clone git@github.com:DEIN_USER/event-planner.git .
    ```

---

## 2. Python-Umgebung einrichten

Wir isolieren die Abhängigkeiten in einer virtuellen Umgebung.

1.  **Virtuelle Umgebung (venv) erstellen:**
    ```bash
    python3 -m venv venv
    ```

2.  **Abhängigkeiten installieren:**
    ```bash
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

3.  **Konfiguration (.env) anlegen:**
    Erstelle die Datei für Umgebungsvariablen manuell (da sie Passwörter enthält, gehört sie nicht ins Git).
    ```bash
    nano .env
    ```
    Inhalt (ersetze die Platzhalter mit deinen echten Strato-Datenbank-Daten):
    ```ini
    FLASK_SECRET_KEY=ein_sehr_langes_zufaelliges_passwort
    SECURITY_PASSWORD_SALT=noch_ein_zufalls_string
    
    # Datenbank (siehe Strato -> Datenbanken verwalten)
    DB_HOST=rdbms.strato.de
    DB_USER=U123456
    DB_PASSWORD=dein_db_passwort
    DB_NAME=DB123456
    
    # Mail-Versand (Optional)
    MAIL_SERVER=smtp.strato.de
    MAIL_PORT=587
    MAIL_USE_TLS=true
    MAIL_USERNAME=info@deine-domain.de
    MAIL_PASSWORD=mail_passwort
    MAIL_DEFAULT_SENDER=info@deine-domain.de
    LOGO_URL=
    ```
    *(Speichern mit `STRG+O`, Beenden mit `STRG+X`)*

4.  **Datenbank initialisieren:**
    ```bash
    mysql -h rdbms.strato.de -u U123456 -p DB123456 < db_schema.sql
    ```

---

## 3. CGI/WSGI Schnittstelle einrichten

Damit der Apache-Server die Python-App ausführt, richten wir eine WSGI-Bridge ein.

1.  **CGI-Ordner erstellen:**
    ```bash
    mkdir cgi-bin
    ```

2.  **Start-Skript (`app.wsgi`) erstellen:**
    ```bash
    nano cgi-bin/app.wsgi
    ```
    Füge folgenden Code ein:
    ```python
    import sys
    import os
    from pathlib import Path
    
    # 1. Pfad zum Projektverzeichnis setzen (ein Ordner über cgi-bin)
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(PROJECT_ROOT))
    
    # 2. Site-Packages aus dem venv hinzufügen (WICHTIG für Strato!)
    # Prüfe ggf. die Python-Version mit 'ls venv/lib/'
    venv_site_packages = PROJECT_ROOT / "venv/lib/python3.10/site-packages"
    if venv_site_packages.exists():
        sys.path.insert(0, str(venv_site_packages))
    
    # 3. Umgebungsvariablen laden
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / '.env')
    
    # 4. Flask App importieren
    from app import app as application
    ```

3.  **Skript ausführbar machen:**
    ```bash
    chmod +x cgi-bin/app.wsgi
    ```

---

## 4. Server-Konfiguration (.htaccess)

Wir leiten alle Anfragen an das Python-Skript weiter.

1.  **CGI aktivieren (`cgi-bin/.htaccess`):**
    ```bash
    nano cgi-bin/.htaccess
    ```
    Inhalt:
    ```apache
    Options +ExecCGI
    AddHandler cgi-script .cgi .py .wsgi
    ```

2.  **Routing einrichten (`.htaccess` im Hauptordner):**
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

## 5. Ersten Admin-User anlegen

Da die Web-Oberfläche geschützt ist, erstellen wir den ersten Admin über die Konsole.

1.  **Python-Shell starten:**
    ```bash
    # Sicherstellen, dass venv aktiv ist
    source venv/bin/activate
    python3
    ```

2.  **User und Event erstellen:**
    Gib folgende Befehle Zeile für Zeile in die Python-Konsole ein:
    ```python
    from app import db, AdminUser, Event, create_app
    import pyotp
    from werkzeug.security import generate_password_hash
    
    app = create_app()
    ctx = app.app_context()
    ctx.push()
    
    # Event anlegen
    event = Event(name='Mein Event', code_prefix='EV', event_date='2025-12-31 18:00', invitation_text='Willkommen!')
    db.session.add(event)
    db.session.commit()
    
    # Admin anlegen
    secret = pyotp.random_base32()
    user = AdminUser(email='admin@deine-domain.de', password_hash=generate_password_hash('DeinPasswort'), totp_secret=secret, role='super_admin')
    db.session.add(user)
    db.session.commit()
    
    print(f"TOTP Secret: {secret}")
    ```

3.  **WICHTIG:** Kopiere das ausgegebene **TOTP Secret** sofort in deine Authenticator App (Google Auth, Authy, etc.). Es wird nicht erneut angezeigt.

---

## 6. Abschluss

1.  **Domain-Umleitung:** Stelle im Strato-Kundenmenü sicher, dass deine Domain auf den Ordner zeigt (z. B. `/einladung`).
2.  **Testen:** Rufe `https://deine-domain.de/admin/login` auf.
3.  **Sicherheit:** Setze in der `.env` `FLASK_DEBUG=0` für den produktiven Betrieb.
