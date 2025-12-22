"""Utility helpers for invite codes, email handling, and PDFs."""

from __future__ import annotations

import hashlib
import logging
import random
from io import BytesIO
from textwrap import wrap
from typing import Iterable, Optional, TYPE_CHECKING

import segno
from flask import current_app
from flask_mail import Message
from reportlab.lib.pagesizes import A6
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from wtforms.validators import Email

from app import mail

if TYPE_CHECKING:
    from app.models import Event, Guest


PBKDF2_ITERATIONS = 200_000
INVITE_CODE_SUFFIX_LENGTH = 6
INVITE_CODE_PATTERN = r"^[A-Za-z]{2}[A-Za-z0-9]{6}$"
ALLOWED_CATEGORIES = (
    "Familie",
    "Nachbarn",
    "Freunde",
    "Arbeit Birgit",
    "Arbeit Olaf",
    "Volleyball",
    "Toastmasters",
)


def normalize_invite_code(code: str) -> str:
    """Normalize an invite code by stripping whitespace and uppercasing it."""

    return (code or "").strip().upper()


def extract_code_prefix(code: str) -> str:
    """Extract the two-character prefix from an invite code."""

    normalized = normalize_invite_code(code)
    return normalized[:2]


def generate_invite_code(prefix: str, suffix_length: int = INVITE_CODE_SUFFIX_LENGTH) -> str:
    """Generate a new invite code using the event prefix and random suffix characters."""

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    suffix = "".join(random.choice(alphabet) for _ in range(suffix_length))
    return f"{prefix.upper()}{suffix}"


def hash_invite_code(code: str) -> str:
    """Generate a deterministic hash for an invite code using PBKDF2."""

    salt = current_app.config.get("SECURITY_PASSWORD_SALT", "").encode("utf-8")
    value = normalize_invite_code(code).encode("utf-8")
    derived_key = hashlib.pbkdf2_hmac("sha256", value, salt, PBKDF2_ITERATIONS)
    return derived_key.hex()


def is_valid_email(value: str) -> bool:
    """Validate an email address string using WTForms' Email validator."""

    if not value:
        return True
    validator = Email()
    try:
        validator(None, type("Tmp", (), {"data": value, "raw_data": [value]}))
    except Exception:
        return False
    return True


def _mail_configured() -> bool:
    """Return True when email configuration is present."""

    return bool(current_app.config.get("MAIL_SERVER") and current_app.config.get("MAIL_DEFAULT_SENDER"))


def send_email(
    subject: str, recipients: list[str], html_body: str, attachments: Optional[list[tuple[str, bytes]]] = None
) -> bool:
    """Send an email with optional PDF attachments, returning False on failure."""

    if not _mail_configured():
        return False
    message = Message(subject=subject, recipients=recipients, html=html_body)
    for filename, content in attachments or []:
        message.attach(filename=filename, content_type="application/pdf", data=content)
    try:
        mail.send(message)
    except Exception:
        logging.getLogger(__name__).exception("Failed to send email")
        return False
    return True


def generate_qr_png(data: str) -> BytesIO:
    """Generate a PNG QR code buffer for the given data."""

    qr = segno.make(data)
    buffer = BytesIO()
    qr.save(buffer, kind="png", scale=5)
    buffer.seek(0)
    return buffer


def build_invite_pdf(guest: "Guest", event: "Event", invite_url: str) -> bytes:
    """Build a PDF invitation including the QR code and event details."""

    qr_buffer = generate_qr_png(invite_url)
    pdf_buffer = BytesIO()
    canvas_obj = canvas.Canvas(pdf_buffer, pagesize=A6)
    width, height = A6
    margin = 10 * mm

    canvas_obj.setFont("Helvetica-Bold", 14)
    canvas_obj.drawString(margin, height - margin - 10, event.name)

    canvas_obj.setFont("Helvetica", 10)
    canvas_obj.drawString(margin, height - margin - 28, f"Für: {guest.first_name} {guest.last_name or ''}".strip())
    canvas_obj.drawString(margin, height - margin - 42, f"Wann: {event.event_date.strftime('%d.%m.%Y %H:%M Uhr')}")

    text_obj = canvas_obj.beginText(margin, height - margin - 64)
    text_obj.setFont("Helvetica", 10)
    text_obj.textLine("Einladungstext:")
    for line in wrap(event.invitation_text or "", width=55):
        text_obj.textLine(line)
    canvas_obj.drawText(text_obj)

    qr_size = 80
    canvas_obj.drawImage(ImageReader(qr_buffer), width - qr_size - margin, margin, qr_size, qr_size, mask="auto")
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawString(margin, margin + qr_size + 4, "QR-Code scannen oder Link öffnen:")
    url_lines = wrap(invite_url, width=60)
    for idx, line in enumerate(url_lines):
        canvas_obj.drawString(margin, margin + qr_size - 10 + (idx * 10), line)

    canvas_obj.showPage()
    canvas_obj.save()
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()


def iter_event_prefixes(events: Iterable["Event"]) -> list[tuple[int, str]]:
    """Return a list of tuples for event IDs and names."""

    return [(event.id, event.name) for event in events if event]
