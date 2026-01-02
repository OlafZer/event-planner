"""Public-facing routes for guests."""

from __future__ import annotations

import re
from html import escape
from typing import Optional

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from wtforms.validators import NumberRange, Optional as OptionalValidator

from app import db, limiter
from app.forms import AccessCodeForm, InviteForm
from app.models import AccessLog, AdminUser, Event, Guest
from app.utils import (
    extract_code_prefix,
    generate_qr_png,
    hash_invite_code,
    normalize_invite_code,
    send_email,
)


public_bp = Blueprint("public", __name__)


def _invite_hash_from_code(code: str) -> Optional[str]:
    """Return a normalized invite hash for the provided code or None if invalid."""

    cleaned = normalize_invite_code(code)
    if len(cleaned) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", cleaned):
        return cleaned.lower()
    if not cleaned:
        return None
    return hash_invite_code(cleaned)


def _get_guest_by_code(event: Event, code: str) -> Guest | None:
    """Return the guest that matches a code for the given event."""

    invite_hash = _invite_hash_from_code(code)
    if invite_hash is None or not re.fullmatch(r"[0-9a-f]{64}", invite_hash):
        return None
    if not (len(code) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", code)):
        if extract_code_prefix(code) != event.code_prefix:
            return None
    return Guest.query.filter_by(event_id=event.id, invite_code_hash=invite_hash).first()


@public_bp.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def index() -> Response | str:
    """Landing page asking guests for their invite code."""

    form = AccessCodeForm()
    if form.validate_on_submit():
        code = normalize_invite_code(form.access_code.data)
        prefix = extract_code_prefix(code)
        event = Event.query.filter_by(code_prefix=prefix).first()
        if not event:
            flash("Dieser Zugangscode wurde nicht gefunden. Bitte prüfe deine Eingabe.", "danger")
            return render_template("index.html", form=form)
        guest = Guest.query.filter_by(event_id=event.id, invite_code_hash=hash_invite_code(code)).first()
        if guest:
            return redirect(url_for("public.invite", event_id=guest.event_id, code=code))
        flash("Dieser Zugangscode wurde nicht gefunden. Bitte prüfe deine Eingabe.", "danger")

    return render_template("index.html", form=form)


@public_bp.route("/event/<int:event_id>/invite/<code>", methods=["GET", "POST"])
@limiter.limit("30 per hour")
def invite(event_id: int, code: str) -> Response | str:
    """Render the invite response form for a guest."""

    event = Event.query.get_or_404(event_id)
    guest = _get_guest_by_code(event, code)
    if not guest:
        return redirect(url_for("public.index"))

    access = AccessLog(
        event_id=event.id,
        guest_id=guest.id,
        user_agent=request.headers.get("User-Agent"),
    )
    db.session.add(access)
    db.session.commit()

    form = InviteForm()
    form.confirmed_persons.validators = [
        OptionalValidator(),
        NumberRange(min=0, max=guest.max_persons, message="Bitte innerhalb der Einladung bleiben."),
    ]

    if form.validate_on_submit():
        guest_status = form.status.data
        guest_notes = form.notes.data
        confirmed = min(form.confirmed_persons.data or 0, guest.max_persons) if guest_status == "zusage" else 0
        guest.notes = guest_notes
        guest.status = guest_status
        guest.confirmed_persons = confirmed
        db.session.commit()
        if guest.notify_admin:
            admins = AdminUser.query.filter(
                (AdminUser.event_id == event.id) | (AdminUser.role == "super_admin")
            ).all()
            recipients = [admin.email for admin in admins if admin.email]
            if recipients:
                notes_html = ""
                if guest_notes:
                    notes_html = f"<p><strong>Besondere Hinweise:</strong> {escape(guest_notes)}</p>"
                sent, error = send_email(
                    subject=f"Status-Update von {guest.first_name} {guest.last_name or ''}",
                    recipients=recipients,
                    html_body=(
                        f"<p>{guest.first_name} {guest.last_name or ''} hat den Status auf <strong>{guest_status}</strong>"
                        f" gesetzt.</p><p>Personen: {confirmed}/{guest.max_persons}</p>{notes_html}"
                    ),
                )
                if not sent:
                    current_app.logger.warning("Status-Update konnte nicht per E-Mail versendet werden: %s", error)
        flash("Danke für deine Rückmeldung!", "success")
        return redirect(url_for("public.invite", event_id=event_id, code=code))

    if request.method == "GET":
        form.status.data = getattr(guest, "status", "save_the_date")
        form.confirmed_persons.data = getattr(guest, "confirmed_persons", 0)
        form.notes.data = getattr(guest, "notes", "")

    return render_template(
        "invite.html",
        guest=guest,
        event=event,
        form=form,
        invite_url=url_for("public.invite", event_id=event.id, code=code, _external=True),
        background_image_url=event.background_image_url,
        code=code,
    )


@public_bp.route("/event/<int:event_id>/invite/<code>/qr")
def invite_qr(event_id: int, code: str) -> Response:
    """Return a QR code PNG for the invite link."""

    event = Event.query.get_or_404(event_id)
    if not _get_guest_by_code(event, code):
        return redirect(url_for("public.index"))
    invite_url = url_for("public.invite", event_id=event.id, code=code, _external=True)
    buffer = generate_qr_png(invite_url)
    return send_file(buffer, mimetype="image/png")
