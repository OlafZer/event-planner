# Anleitung: Demo-Instanz mit Ansible erstellen

## Voraussetzungen

- Python-Abhängigkeiten installiert (`pip install -r requirements.txt`)
- Ansible installiert (mindestens 2.12)
- Eine konfigurierte `.env` mit Datenbank- und SMTP-Zugangsdaten
  - `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
  - `MAIL_SERVER`, `MAIL_PORT`, `MAIL_DEFAULT_SENDER`
  - Optional: `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_USE_TLS`, `MAIL_USE_SSL`

## Playbook ausführen

1. Optional: Demo-Admin-E-Mail setzen.

   ```bash
   ansible-playbook playbook_demo.yml -e "demo_admin_email=demo-admin@example.com"
   ```

2. Das Playbook legt eine Sicherung der Datenbank an, setzt sie zurück, erstellt Demo-Daten
   und sendet das Log per E-Mail.

## Neues Playbook `create_demo_instance.yml`

Dieses Playbook nutzt die headless Skripte (`scripts/create_admin.py`, `scripts/create_demo_data.py`,
`scripts/send_demo_log.py`), führt alle Befehle im virtuellen Environment aus und protokolliert die
Invite-Codes strukturiert.

Beispielaufruf:

```bash
ansible-playbook create_demo_instance.yml \
  -e "demo_admin_email=demo-admin@example.com" \
  -e "guests_per_event=20" \
  -e "update_env_admin=true"
```

## Ergebnisdateien

- `.demo_env` enthält die Zugangsdaten des Demo-Admins.
- `YYYYMMTTHHMMSS_event_planner_Demo.txt` enthält das vollständige Demo-Log (Credentials, TOTP-Secret, DB-Output, Invite-Codes).
- `backups/` enthält das Datenbank-Backup.

## Hinweise

- Für `event_admin` Accounts kann `scripts/create_admin_headless.py` mit `--event-id` genutzt werden.
- Die E-Mail wird standardmäßig an `MAIL_DEFAULT_SENDER` gesendet. Optional kann `scripts/send_demo_log.py` mit `--recipient` genutzt werden.
