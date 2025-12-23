"""Headless helper to create admin users including their TOTP secret.

This script is safe to run on Strato (no interactive prompts, no compilers).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyotp
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Ensure the project root is importable when running from the scripts/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app, db
from app.models import AdminUser, Event


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create an admin user without interactive prompts.")
    parser.add_argument("--email", required=True, help="Admin-E-Mail-Adresse")
    parser.add_argument("--password", required=True, help="Passwort für den Admin")
    parser.add_argument(
        "--role",
        choices=["super_admin", "event_admin"],
        default="super_admin",
        help="Rolle des Admins",
    )
    parser.add_argument(
        "--event-id",
        type=int,
        help="Event-ID (erforderlich für event_admin)",
    )
    parser.add_argument(
        "--fail-on-existing",
        action="store_true",
        help="Mit Exit-Code 1 abbrechen, falls der Admin bereits existiert.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    load_dotenv()
    app = create_app()

    with app.app_context():
        existing = AdminUser.query.filter_by(email=args.email).first()
        if existing:
            print(f"Admin mit der E-Mail {args.email} existiert bereits.")
            return 1 if args.fail_on_existing else 0

        assigned_event = None
        if args.role == "event_admin":
            if not args.event_id:
                print("Für event_admin muss --event-id angegeben werden.", file=sys.stderr)
                return 1
            assigned_event = Event.query.get(args.event_id)
            if not assigned_event:
                print(f"Kein Event mit ID {args.event_id} gefunden.", file=sys.stderr)
                return 1

        secret = pyotp.random_base32()
        user = AdminUser(
            email=args.email,
            password_hash=generate_password_hash(args.password),
            totp_secret=secret,
            role=args.role,
            event=assigned_event,
        )
        db.session.add(user)
        db.session.commit()

        print(f"ADMIN_EMAIL={user.email}")
        print(f"ADMIN_ROLE={user.role}")
        print(f"ADMIN_ID={user.id}")
        if assigned_event:
            print(f"ADMIN_EVENT_ID={assigned_event.id}")
        print(f"TOTP_SECRET={secret}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
