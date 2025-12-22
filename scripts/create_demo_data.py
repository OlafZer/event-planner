"""Demo-Daten für lokale Entwicklung erzeugen."""

import random
from datetime import datetime, timedelta

from dotenv import load_dotenv
from faker import Faker

from app import create_app, db
from app.models import Event, Guest
from app.utils import ALLOWED_CATEGORIES, generate_invite_code, hash_invite_code

load_dotenv()
faker = Faker("de_DE")
app = create_app()


def create_demo_events() -> None:
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

    with app.app_context():
        for entry in demo_events:
            existing = Event.query.filter_by(name=entry["name"]).first()
            if existing:
                event = existing
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
            create_demo_guests(event)
        db.session.commit()


def create_demo_guests(event: Event, count: int = 15) -> None:
    """Generate demo guests for the given event."""
    status_choices = ["safe_the_date", "zusage", "absage", "unsicher"]
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
    print(f"{count} Gäste für {event.name} vorbereitet.")


if __name__ == "__main__":
    create_demo_events()
    print("Demo-Daten wurden erstellt.")
