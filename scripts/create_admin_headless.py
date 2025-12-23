"""
Headless script to create an admin user from CLI arguments.

Usage:
    python scripts/create_admin_headless.py --email admin@example.com --password "secret" --role super_admin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyotp
from werkzeug.security import generate_password_hash

# Ensure the project root is importable when running from the scripts/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app, db
from app.models import AdminUser, Event


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create an admin user non-interactively.")
    parser.add_argument("--email", required=True, help="Admin email address")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument(
        "--role",
        default="super_admin",
        choices=["super_admin", "event_admin"],
        help="Admin role",
    )
    parser.add_argument(
        "--event-id",
        type=int,
        default=None,
        help="Event ID to assign when using event_admin role",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    app = create_app()

    with app.app_context():
        existing = AdminUser.query.filter_by(email=args.email).first()
        if existing:
            print(f"Es existiert bereits ein Admin mit der E-Mail {args.email}.", file=sys.stderr)
            return 1

        assigned_event = None
        if args.role == "event_admin":
            if not args.event_id:
                print("Event-ID ist für event_admin erforderlich.", file=sys.stderr)
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

    print("Admin erfolgreich angelegt.")
    print(f"E-Mail: {args.email}")
    print(f"Rolle: {args.role}")
    if assigned_event:
        print(f"Event: {assigned_event.id} - {assigned_event.name}")
    print(f"TOTP-Secret: {secret}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
