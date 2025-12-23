"""
Send the demo log file via SMTP using settings from the .env file.

Usage:
    python scripts/send_demo_log.py --log-file path/to/log.txt [--recipient someone@example.com]
"""

from __future__ import annotations

import argparse
import os
import sys
from email.message import EmailMessage
from pathlib import Path
from smtplib import SMTP, SMTP_SSL

from dotenv import load_dotenv


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send the demo log file via SMTP.")
    parser.add_argument("--log-file", required=True, help="Path to the demo log file")
    parser.add_argument("--recipient", help="Optional recipient address (defaults to MAIL_DEFAULT_SENDER)")
    parser.add_argument("--subject", default="Event Planner Demo Log", help="Email subject")
    return parser.parse_args()


def _env_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def main() -> int:
    args = _parse_args()
    load_dotenv()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Log-Datei nicht gefunden: {log_path}", file=sys.stderr)
        return 1

    mail_server = os.getenv("MAIL_SERVER")
    mail_port = int(os.getenv("MAIL_PORT", "587"))
    mail_use_tls = _env_bool(os.getenv("MAIL_USE_TLS"), default=True)
    mail_use_ssl = _env_bool(os.getenv("MAIL_USE_SSL"))
    mail_username = os.getenv("MAIL_USERNAME")
    mail_password = os.getenv("MAIL_PASSWORD")
    mail_sender = os.getenv("MAIL_DEFAULT_SENDER")
    recipient = args.recipient or mail_sender

    if not mail_server or not mail_sender or not recipient:
        print("SMTP-Konfiguration unvollständig. MAIL_SERVER und MAIL_DEFAULT_SENDER sind erforderlich.", file=sys.stderr)
        return 1

    message = EmailMessage()
    message["Subject"] = args.subject
    message["From"] = mail_sender
    message["To"] = recipient
    log_content = log_path.read_text(encoding="utf-8")
    message.set_content(
        "Im Anhang befindet sich das Demo-Log der Event-Planner-Instanz.\n\n" + log_content
    )
    message.add_attachment(
        log_content.encode("utf-8"),
        maintype="text",
        subtype="plain",
        filename=log_path.name,
    )

    smtp_class = SMTP_SSL if mail_use_ssl else SMTP
    with smtp_class(mail_server, mail_port, timeout=30) as smtp:
        if not mail_use_ssl and mail_use_tls:
            smtp.starttls()
        if mail_username and mail_password:
            smtp.login(mail_username, mail_password)
        smtp.send_message(message)

    print(f"E-Mail wurde an {recipient} versendet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
