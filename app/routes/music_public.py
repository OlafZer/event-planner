"""Public routes for guests to manage their music requests."""

from __future__ import annotations

import re

from flask import Blueprint, Response, flash, redirect, render_template, url_for

from app import db
from app.forms import MusicRequestForm
from app.models import Event, Guest, MusicRequest
from app.utils import extract_code_prefix, hash_invite_code, normalize_invite_code


music_public_bp = Blueprint("music_public", __name__)


def _invite_hash_from_code(code: str) -> str | None:
    """Return a normalized invite hash for the provided code or None if invalid."""

    cleaned = normalize_invite_code(code)
    if len(cleaned) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", cleaned):
        return cleaned.lower()
    if not cleaned:
        return None
    return hash_invite_code(cleaned)


def _get_guest_from_code(event: Event, code: str) -> Guest | None:
    """Look up a guest for an event by invite code or invite hash."""

    invite_hash = _invite_hash_from_code(code)
    if invite_hash is None or not re.fullmatch(r"[0-9a-f]{64}", invite_hash):
        return None
    if not (len(code) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", code)):
        if extract_code_prefix(code) != event.code_prefix:
            return None
    return Guest.query.filter_by(event_id=event.id, invite_code_hash=invite_hash).first()


@music_public_bp.route("/event/<int:event_id>/invite/<code>/music", methods=["GET", "POST"])
def music_request_page(event_id: int, code: str) -> Response | str:
    """Allow guests to submit and manage their music requests."""

    event = Event.query.get_or_404(event_id)
    guest = _get_guest_from_code(event, code)
    if not guest:
        flash("Ungültiger Zugangscode.", "danger")
        return redirect(url_for("public.index"))

    if not event.music_requests_enabled:
        flash("Musikwünsche sind für dieses Event nicht verfügbar.", "info")
        return redirect(url_for("public.invite", event_id=event_id, code=code))

    form = MusicRequestForm()
    if form.validate_on_submit():
        music_request = MusicRequest(
            event_id=event.id,
            guest_id=guest.id,
            artist=form.artist.data.strip(),
            title=form.title.data.strip(),
            notes=form.notes.data.strip() if form.notes.data else None,
        )
        db.session.add(music_request)
        db.session.commit()
        flash(f"Musikwunsch gespeichert: {music_request.artist} - {music_request.title}", "success")
        return redirect(url_for("music_public.music_request_page", event_id=event_id, code=code))

    guest_requests = (
        MusicRequest.query.filter_by(event_id=event.id, guest_id=guest.id)
        .order_by(MusicRequest.created_at.desc())
        .all()
    )

    return render_template(
        "music_request_page.html",
        event=event,
        guest=guest,
        form=form,
        guest_requests=guest_requests,
        code=code,
        background_image_url=event.background_image_url,
    )


@music_public_bp.route("/event/<int:event_id>/invite/<code>/music/delete/<int:request_id>", methods=["POST"])
def delete_own_music_request(event_id: int, code: str, request_id: int) -> Response:
    """Allow guests to delete their own music requests."""

    event = Event.query.get_or_404(event_id)
    guest = _get_guest_from_code(event, code)
    if not guest:
        flash("Ungültiger Zugangscode.", "danger")
        return redirect(url_for("public.index"))

    music_request = MusicRequest.query.filter_by(id=request_id, event_id=event.id, guest_id=guest.id).first_or_404()
    artist = music_request.artist
    title = music_request.title
    db.session.delete(music_request)
    db.session.commit()
    flash(f"Musikwunsch '{artist} - {title}' wurde gelöscht.", "success")
    return redirect(url_for("music_public.music_request_page", event_id=event_id, code=code))
