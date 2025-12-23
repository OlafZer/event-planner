"""Send the demo log file using the Flask-Mail configuration from the app factory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv
from flask import current_app
from flask_mail import Message

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app, mail


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send the demo log file via Flask-Mail.")
    parser.add_argument("--log-file", required=True, help="Path to the demo log file")
    parser.add_argument("--recipient", help="Optional recipient address (defaults to MAIL_DEFAULT_SENDER)")
    parser.add_argument("--subject", default="Event Planner Demo Log", help="Email subject")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    load_dotenv()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Log-Datei nicht gefunden: {log_path}", file=sys.stderr)
        return 1

    app = create_app()
    with app.app_context():
        sender = current_app.config.get("MAIL_DEFAULT_SENDER")
        recipient = args.recipient or sender
        mail_server = current_app.config.get("MAIL_SERVER")
        if not mail_server or not sender or not recipient:
            print(
                "SMTP-Konfiguration unvollständig. MAIL_SERVER und MAIL_DEFAULT_SENDER sind erforderlich.",
                file=sys.stderr,
            )
            return 1

        log_content = log_path.read_text(encoding="utf-8")
        message = Message(
            subject=args.subject,
            sender=sender,
            recipients=[recipient],
            body="Im Anhang befindet sich das Demo-Log der Event-Planner-Instanz.",
        )
        message.attach(filename=log_path.name, content_type="text/plain", data=log_content)
        try:
            mail.send(message)
        except Exception as exc:  # pragma: no cover - defensive logging for ops usage
            print(f"E-Mail Versand fehlgeschlagen: {exc}", file=sys.stderr)
            return 1

    print(f"E-Mail wurde an {recipient} versendet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
