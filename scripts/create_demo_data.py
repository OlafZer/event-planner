"""Demo-Daten erzeugen und Invite-Codes strukturiert ausgeben."""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from faker import Faker

# Ensure the project root is importable when running from the scripts/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app, db
from app.models import Event, Guest
from app.utils import ALLOWED_CATEGORIES, generate_invite_code, hash_invite_code

faker = Faker("de_DE")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Erzeuge Demo-Daten ohne Benutzerinteraktion.")
    parser.add_argument(
        "--guests-per-event",
        type=int,
        default=15,
        help="Anzahl der Gäste pro Event",
    )
    return parser.parse_args()


def create_demo_events(guests_per_event: int) -> list[tuple[str, str, str]]:
    """Create demo events with fixed prefixes for local development."""
    demo_events = [
        {
            "name": "Sommerfest",
            "description": "Grillen, Musik und kalte Getränke im Garten.",
            "days_in_future": 30,
            "background_image_url": "https://source.unsplash.com/featured/?summer,party",
            "invitation_text": "Wir freuen uns auf einen warmen Abend mit dir. Bring gerne gute Laune mit!",
            "code_prefix": "SO",
        },
        {
            "name": "Weihnachtsfeier",
            "description": "Gemütliches Beisammensein mit Punsch und Plätzchen.",
            "days_in_future": 90,
            "background_image_url": "https://source.unsplash.com/featured/?christmas,lights",
            "invitation_text": "Zieh den ugly Christmas Sweater an und feier mit uns!",
            "code_prefix": "WE",
        },
    ]

    invite_codes: list[tuple[str, str, str]] = []
    for entry in demo_events:
        event = Event.query.filter_by(name=entry["name"]).first()
        if event:
            if event.code_prefix != entry["code_prefix"]:
                event.code_prefix = entry["code_prefix"]
                db.session.add(event)
        else:
            event = Event(
                name=entry["name"],
                description=entry["description"],
                event_date=datetime.utcnow() + timedelta(days=entry["days_in_future"]),
                invitation_text=entry["invitation_text"],
                background_image_url=entry["background_image_url"],
                code_prefix=entry["code_prefix"],
            )
            db.session.add(event)
            db.session.commit()
        invite_codes.extend(create_demo_guests(event, guests_per_event))
    db.session.commit()
    return invite_codes


def create_demo_guests(event: Event, count: int) -> list[tuple[str, str, str]]:
    """Generate demo guests for the given event."""
    status_choices = ["safe_the_date", "zusage", "absage", "unsicher"]
    invite_codes: list[tuple[str, str, str]] = []
    for _ in range(count):
        first_name = faker.first_name()
        last_name = faker.last_name()
        invite_code = generate_invite_code(event.code_prefix)
        guest = Guest(
            event_id=event.id,
            first_name=first_name,
            last_name=last_name,
            category=random.choice(ALLOWED_CATEGORIES),
            max_persons=random.randint(1, 4),
            invite_code_hash=hash_invite_code(invite_code),
            email=faker.email(),
            telephone=faker.phone_number(),
            status=random.choice(status_choices),
            confirmed_persons=random.randint(0, 3),
            notify_admin=random.choice([True, False]),
        )
        db.session.add(guest)
        invite_codes.append((event.name, f"{first_name} {last_name}", invite_code))
    return invite_codes


def main() -> int:
    args = _parse_args()
    if args.guests_per_event < 1:
        print("Die Anzahl Gäste pro Event muss mindestens 1 sein.", file=sys.stderr)
        return 1

    load_dotenv()
    app = create_app()
    with app.app_context():
        codes = create_demo_events(args.guests_per_event)

    print("INVITE_CODES_START")
    for event_name, guest_name, invite_code in codes:
        print(f"INVITE_CODE|{event_name}|{guest_name}|{invite_code}")
    print("INVITE_CODES_END")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
