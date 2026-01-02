"""Admin routes for managing music requests per event."""

from __future__ import annotations

import csv
from io import BytesIO, StringIO

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from app import db
from app.forms import MusicRequestEnableForm
from app.models import Event, Guest, MusicRequest


music_admin_bp = Blueprint("music_admin", __name__, url_prefix="/admin")


def _sanitize_csv_cell(value: str | None) -> str:
    """Prefix potentially dangerous CSV values to avoid formula injection."""

    if value is None:
        return ""
    stripped = value.strip()
    if stripped.startswith(("=", "+", "-", "@")):
        return f"'{stripped}"
    return stripped


def _require_event_access(event_id: int) -> None:
    """Ensure the current admin can access the given event."""

    if current_user.is_super_admin:
        return
    if not current_user.event_id or current_user.event_id != event_id:
        abort(403)


@music_admin_bp.route("/event/<int:event_id>/music", methods=["GET", "POST"])
@login_required
def music_settings(event_id: int) -> Response | str:
    """Toggle music requests and show statistics for an event."""

    _require_event_access(event_id)
    event = Event.query.get_or_404(event_id)
    if not current_app.config.get("MUSIC_REQUESTS_AVAILABLE", True):
        flash(
            current_app.config.get("MUSIC_REQUESTS_ERROR")
            or "Musikwünsche sind derzeit nicht verfügbar. Bitte Migration prüfen.",
            "danger",
        )
        return redirect(url_for("admin.admin_dashboard", event_id=event_id))
    form = MusicRequestEnableForm()

    if form.validate_on_submit():
        event.music_requests_enabled = bool(form.music_requests_enabled.data)
        db.session.commit()
        if event.music_requests_enabled:
            flash("Musikwünsche aktiviert! Gäste können jetzt Wünsche eingeben.", "success")
        else:
            flash("Musikwünsche deaktiviert.", "info")
        return redirect(url_for("music_admin.music_settings", event_id=event_id))

    if request.method == "GET":
        form.music_requests_enabled.data = event.music_requests_enabled

    total_requests = MusicRequest.query.filter_by(event_id=event.id).count()
    unique_guests = (
        db.session.query(db.func.count(db.func.distinct(MusicRequest.guest_id)))
        .filter_by(event_id=event.id)
        .scalar()
        or 0
    )
    recent_requests = (
        db.session.query(MusicRequest, Guest)
        .join(Guest, MusicRequest.guest_id == Guest.id)
        .filter(MusicRequest.event_id == event.id)
        .order_by(MusicRequest.created_at.desc())
        .limit(10)
        .all()
    )

    stats = {
        "total_requests": total_requests,
        "unique_guests": unique_guests,
        "recent_requests": recent_requests,
    }

    return render_template("admin_music_settings.html", event=event, form=form, stats=stats)


@music_admin_bp.route("/event/<int:event_id>/music/requests")
@login_required
def music_requests_list(event_id: int) -> Response | str:
    """List all music requests for an event."""

    _require_event_access(event_id)
    event = Event.query.get_or_404(event_id)
    if not current_app.config.get("MUSIC_REQUESTS_AVAILABLE", True):
        flash(
            current_app.config.get("MUSIC_REQUESTS_ERROR")
            or "Musikwünsche sind derzeit nicht verfügbar. Bitte Migration prüfen.",
            "danger",
        )
        return redirect(url_for("admin.admin_dashboard", event_id=event_id))
    if not event.music_requests_enabled:
        flash("Musikwünsche sind für dieses Event nicht aktiviert.", "warning")
        return redirect(url_for("admin.admin_dashboard", event_id=event_id))

    requests = (
        db.session.query(MusicRequest, Guest)
        .join(Guest, MusicRequest.guest_id == Guest.id)
        .filter(MusicRequest.event_id == event.id)
        .order_by(MusicRequest.created_at.desc())
        .all()
    )

    return render_template("admin_music_requests.html", event=event, requests=requests)


@music_admin_bp.route("/event/<int:event_id>/music/export")
@login_required
def export_music_requests(event_id: int) -> Response:
    """Export music requests for an event as CSV."""

    _require_event_access(event_id)
    event = Event.query.get_or_404(event_id)
    if not current_app.config.get("MUSIC_REQUESTS_AVAILABLE", True):
        flash(
            current_app.config.get("MUSIC_REQUESTS_ERROR")
            or "Musikwünsche sind derzeit nicht verfügbar. Bitte Migration prüfen.",
            "danger",
        )
        return redirect(url_for("admin.admin_dashboard", event_id=event_id))
    requests = (
        db.session.query(MusicRequest, Guest)
        .join(Guest, MusicRequest.guest_id == Guest.id)
        .filter(MusicRequest.event_id == event.id)
        .order_by(MusicRequest.artist, MusicRequest.title)
        .all()
    )

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Interpret",
            "Titel",
            "Gast ID",
            "Gast Name",
            "Gast Kategorie",
            "Anmerkung",
            "Eingereicht am",
            "Spotify Track ID",
        ]
    )
    for music_request, guest in requests:
        writer.writerow(
            [
                _sanitize_csv_cell(music_request.artist),
                _sanitize_csv_cell(music_request.title),
                guest.id,
                _sanitize_csv_cell(f"{guest.first_name} {guest.last_name or ''}".strip()),
                _sanitize_csv_cell(guest.category),
                _sanitize_csv_cell(music_request.notes),
                music_request.created_at.strftime("%Y-%m-%d %H:%M:%S") if music_request.created_at else "",
                music_request.spotify_track_id or "",
            ]
        )

    csv_bytes = BytesIO(output.getvalue().encode("utf-8"))
    filename = f"musikwuensche_{event.name.replace(' ', '_')}_{event.id}.csv"
    return send_file(csv_bytes, mimetype="text/csv", as_attachment=True, download_name=filename)


@music_admin_bp.route("/event/<int:event_id>/music/request/<int:request_id>/delete", methods=["POST"])
@login_required
def delete_music_request(event_id: int, request_id: int) -> Response:
    """Delete a music request as admin."""

    _require_event_access(event_id)
    if not current_app.config.get("MUSIC_REQUESTS_AVAILABLE", True):
        flash(
            current_app.config.get("MUSIC_REQUESTS_ERROR")
            or "Musikwünsche sind derzeit nicht verfügbar. Bitte Migration prüfen.",
            "danger",
        )
        return redirect(url_for("admin.admin_dashboard", event_id=event_id))
    music_request = MusicRequest.query.filter_by(id=request_id, event_id=event_id).first_or_404()
    artist = music_request.artist
    title = music_request.title
    db.session.delete(music_request)
    db.session.commit()
    flash(f"Musikwunsch '{artist} - {title}' wurde gelöscht.", "success")
    return redirect(url_for("music_admin.music_requests_list", event_id=event_id))
