"""import_guests.py

Synopsis:
    Importiert Gaeste fuer ein Event aus einer CSV-Datei.

Verwendung:
    python -m scripts.import_guests --event-id 1 --csv guests.csv

CSV-Format (Header-Zeile erforderlich):
    name, nachname, kategorie, max_persons, invite_code, email, telephone, notify_admin

Spaltenhinweise:
    - name (Pflicht) wird zu first_name
    - nachname optional
    - kategorie muss in ALLOWED_CATEGORIES liegen
    - max_persons muss eine Zahl >= 1 sein
    - invite_code wird gehasht und als invite_code_hash gespeichert
    - email ist optional (Spalte Pflicht, Wert pro Zeile optional)
    - telephone optional
    - notify_admin wird als bool interpretiert (1/true/yes/ja)
"""

import argparse
import csv
import sys

from app import ALLOWED_CATEGORIES, Event, Guest, app, db, hash_invite_code
from wtforms.validators import Email


TRUE_VALUES = {"1", "true", "yes", "ja", "y"}


def _validate_email(value: str) -> bool:
    if not value:
        return True
    validator = Email()
    try:
        validator(None, type("Tmp", (), {"data": value, "raw_data": [value]}))
    except Exception:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Gaeste per CSV importieren")
    parser.add_argument("--event-id", type=int, required=True, help="Ziel-Event-ID")
    parser.add_argument("--csv", required=True, help="Pfad zur CSV-Datei")
    args = parser.parse_args()

    with app.app_context():
        event = Event.query.get(args.event_id)
        if not event:
            sys.exit(f"Event mit ID {args.event_id} nicht gefunden")

        with open(args.csv, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            required_headers = {
                "name",
                "nachname",
                "kategorie",
                "max_persons",
                "invite_code",
                "email",
                "telephone",
                "notify_admin",
            }
            if set(reader.fieldnames or []) != required_headers:
                sys.exit(
                    "CSV-Header stimmen nicht: erwartet name, nachname, kategorie, max_persons, invite_code, email, telephone, notify_admin"
                )

            imported = 0
            for row in reader:
                first_name = (row.get("name") or "").strip()
                last_name = (row.get("nachname") or "").strip() or None
                category = (row.get("kategorie") or "").strip()
                max_persons_raw = (row.get("max_persons") or "").strip()
                invite_code = (row.get("invite_code") or "").strip()
                email = (row.get("email") or "").strip() or None
                telephone = (row.get("telephone") or "").strip() or None
                notify_raw = (row.get("notify_admin") or "").strip().lower()

                if not first_name:
                    print("Zeile ohne Namen übersprungen", file=sys.stderr)
                    continue
                if category not in ALLOWED_CATEGORIES:
                    print(f"Kategorie {category} nicht erlaubt", file=sys.stderr)
                    continue
                try:
                    max_persons = int(max_persons_raw)
                except ValueError:
                    print("max_persons muss eine Zahl sein", file=sys.stderr)
                    continue
                if max_persons < 1:
                    print("max_persons muss >= 1 sein", file=sys.stderr)
                    continue
                if not invite_code:
                    print("Invite-Code fehlt", file=sys.stderr)
                    continue
                if email and not _validate_email(email):
                    print(f"Ungültige E-Mail: {email}", file=sys.stderr)
                    continue

                code_hash = hash_invite_code(invite_code)
                if Guest.query.filter_by(event_id=event.id, invite_code_hash=code_hash).first():
                    print("Invite-Code bereits vergeben", file=sys.stderr)
                    continue

                notify_admin_value = notify_raw in TRUE_VALUES

                guest = Guest(
                    event_id=event.id,
                    first_name=first_name,
                    last_name=last_name,
                    category=category,
                    max_persons=max_persons,
                    invite_code_hash=code_hash,
                    email=email,
                    telephone=telephone,
                    notify_admin=notify_admin_value,
                )
                db.session.add(guest)
                imported += 1
            db.session.commit()
            print(f"{imported} Gäste importiert")


if __name__ == "__main__":
    main()
