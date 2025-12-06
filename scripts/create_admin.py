"""
Hilfsskript zum Anlegen eines Admin-Users mit TOTP-Secret.

Kann sowohl lokal als auch auf dem Strato-Server verwendet werden.
Voraussetzung:
- app, db, AdminUser, Event in app.py definiert
- .env mit gültigen DB-Zugangsdaten
"""

import getpass
import sys
from pathlib import Path

import pyotp
from werkzeug.security import generate_password_hash

# Ensure the project root (containing app.py) is importable when running from the
# scripts/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import app, db, AdminUser, Event


def main():
    print("=== Admin-User anlegen ===")

    email = input("Admin-E-Mail: ").strip()
    if not email:
        print("E-Mail darf nicht leer sein.")
        return

    password = getpass.getpass("Passwort fuer den Admin: ")
    if not password:
        print("Passwort darf nicht leer sein.")
        return

    role = input("Rolle [super_admin/event_admin] (Default: super_admin): ").strip() or "super_admin"
    if role not in ("super_admin", "event_admin"):
        print("Ungueltige Rolle, erwarte 'super_admin' oder 'event_admin'.")
        return

    # Optional: Event verknuepfen (nur relevant fuer event_admin)
    assigned_event = None
    if role == "event_admin":
        event_name = input("Name des Events fuer diesen Admin (optional, Enter fuer kein Event): ").strip()
        if event_name:
            # Event nach Name suchen oder neu anlegen
            assigned_event = Event.query.filter_by(name=event_name).first()
            if not assigned_event:
                desc = input("Beschreibung fuer das Event (optional): ").strip()
                assigned_event = Event(name=event_name, description=desc or None)
                db.session.add(assigned_event)
                db.session.commit()
                print(f"Event angelegt: id={assigned_event.id}, name={assigned_event.name}")

    with app.app_context():
        # Pruefen, ob es die E-Mail schon gibt
        existing = AdminUser.query.filter_by(email=email).first()
        if existing:
            print(f"Es existiert bereits ein Admin mit der E-Mail {email}. Abbruch.")
            return

        # TOTP-Secret erzeugen
        secret = pyotp.random_base32()

        user_kwargs = {
            "email": email,
            "password_hash": generate_password_hash(password),
            "totp_secret": secret,
            "role": role,
        }

        # Falls das Modell ein assigned_event_id oder eine Beziehung hat
        # kannst du es hier ggf. anpassen – diese Variante geht davon aus,
        # dass du bei event_admin ein Event zuweisen kannst, es bei super_admin aber ignoriert wird.
        if role == "event_admin" and assigned_event is not None:
            # Viele ORMs haben entweder assigned_event oder assigned_event_id – passe das ggf. an.
            # Wenn dein Modell ein Feld "assigned_event_id" hat:
            user_kwargs["assigned_event_id"] = assigned_event.id

        user = AdminUser(**user_kwargs)
        db.session.add(user)
        db.session.commit()

        print("\nAdmin erfolgreich angelegt:")
        print(f"  E-Mail: {user.email}")
        print(f"  Rolle:  {user.role}")
        if role == "event_admin" and assigned_event is not None:
            print(f"  Event:  {assigned_event.id} - {assigned_event.name}")

        print("\nTOTP-Secret (fuer deine Authenticator-App):")
        print(f"  {secret}")
        print("\nDieses Secret musst du in einer TOTP-App (z.B. Google Authenticator) als neues Konto hinterlegen.")
        print("Danach kannst du dich mit E-Mail + Passwort + TOTP-Code anmelden.")


if __name__ == "__main__":
    # App-Context sicherstellen
    with app.app_context():
        main()

