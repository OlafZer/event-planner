"""create_admin.py

Synopsis:
    Legt einen Admin-User mit Passwort und optionalem Event an.

Verwendung:
    python -m scripts.create_admin --email admin@example.com --role super_admin
    python -m scripts.create_admin --email eventadmin@example.com --event-id 1

Das Skript fragt das Passwort interaktiv ab und läuft im App-Kontext.
"""

import argparse
import getpass

from app import app, create_admin_user, db, Event


def main():
    parser = argparse.ArgumentParser(description="Admin-User anlegen")
    parser.add_argument("--email", required=True, help="E-Mail des neuen Admins")
    parser.add_argument(
        "--role",
        choices=["super_admin", "event_admin"],
        default="event_admin",
        help="Rolle des Admins",
    )
    parser.add_argument("--event-id", type=int, help="Event-ID für event_admin")
    args = parser.parse_args()

    with app.app_context():
        event = None
        if args.role == "event_admin":
            if not args.event_id:
                parser.error("--event-id ist für event_admin erforderlich")
            event = Event.query.get(args.event_id)
            if not event:
                parser.error(f"Event mit ID {args.event_id} nicht gefunden")
        password = getpass.getpass("Passwort: ")
        if not password:
            parser.error("Passwort darf nicht leer sein")
        user = create_admin_user(args.email, password, args.role, event)
        print(f"Admin {user.email} angelegt. TOTP-URI: {user.generate_totp_uri()}")


if __name__ == "__main__":
    main()
