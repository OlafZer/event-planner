"""Admin routes for managing events and guests."""

from __future__ import annotations

import csv
import re
from io import BytesIO
from typing import Iterable, Optional

import pyotp
from flask import Blueprint, Response, abort, flash, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash

from app import db, login_manager
from app.forms import (
    AdminLoginForm,
    AdminTotpForm,
    CsvUploadForm,
    EventCreateForm,
    GuestActionForm,
    GuestForm,
)
from app.models import AdminUser, Event, Guest
from app.utils import (
    ALLOWED_CATEGORIES,
    INVITE_CODE_PATTERN,
    build_invite_pdf,
    hash_invite_code,
    is_valid_email,
    normalize_invite_code,
    send_email,
)


admin_bp = Blueprint("admin", __name__)


@login_manager.user_loader
def load_user(user_id: str) -> AdminUser | None:
    """Load an admin user by ID for the login manager."""

    return AdminUser.query.get(int(user_id))


def create_admin_user(
    email: str, password: str, role: str = "event_admin", event: Optional[Event] = None
) -> AdminUser:
    """Create and persist a new admin user with a hashed password."""

    secret = pyotp.random_base32()
    password_hash = generate_password_hash(password)
    user = AdminUser(
        email=email,
        password_hash=password_hash,
        totp_secret=secret,
        role=role,
        event=event,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _require_event_access(event_id: int) -> None:
    """Abort the request if the current user lacks access to the event."""

    if current_user.is_super_admin:
        return
    if not current_user.event_id or current_user.event_id != event_id:
        abort(403)


def _validate_invite_code_for_event(code: str, event: Event) -> Optional[str]:
    """Validate the invite code format and ensure the prefix matches the event."""

    normalized = normalize_invite_code(code)
    if not re.fullmatch(INVITE_CODE_PATTERN, normalized):
        return None
    if normalized[:2] != event.code_prefix:
        return None
    return normalized


def _prepare_manual_invite_code(code: str, event: Event) -> Optional[str]:
    """Build a full invite code for manual entry based on the event prefix."""

    normalized = normalize_invite_code(code)
    if re.fullmatch(INVITE_CODE_PATTERN, normalized):
        return normalized if normalized[:2] == event.code_prefix else None
    suffix = normalized.lstrip("-")
    if not re.fullmatch(r"^[A-Z0-9]{5}$", suffix):
        return None
    return f"{event.code_prefix}-{suffix}"


@admin_bp.route("/admin/login", methods=["GET", "POST"])
def admin_login() -> Response | str:
    """Render the admin login form and handle authentication."""

    if current_user.is_authenticated:
        return redirect(url_for("admin.admin_dashboard"))

    form = AdminLoginForm()
    if form.validate_on_submit():
        user = AdminUser.query.filter_by(email=form.email.data).first()
        if user and user.verify_password(form.password.data):
            session["pre_2fa_user_id"] = user.id
            return redirect(url_for("admin.admin_totp"))
        flash("Ungültige Zugangsdaten", "danger")
    return render_template("admin_login.html", form=form)


@admin_bp.route("/login/admin", methods=["GET", "POST"])
def admin_login_alias() -> Response | str:
    """Backward-compatible alias that forwards to the admin login page."""

    return admin_login()


@admin_bp.route("/admin/totp", methods=["GET", "POST"])
def admin_totp() -> Response | str:
    """Validate the TOTP token and log the admin in."""

    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("admin.admin_login"))

    user = AdminUser.query.get_or_404(user_id)
    form = AdminTotpForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.token.data, valid_window=1):
            login_user(user)
            session.pop("pre_2fa_user_id", None)
            return redirect(url_for("admin.admin_dashboard"))
        flash("TOTP-Code ungültig oder abgelaufen", "danger")
    return render_template("admin_totp.html", form=form)


@admin_bp.route("/admin/logout")
@login_required
def admin_logout() -> Response:
    """Log the admin user out and redirect to login."""

    logout_user()
    return redirect(url_for("admin.admin_login"))


@admin_bp.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard() -> Response | str:
    """Render the admin dashboard for managing events and guests."""

    requested_event_id = request.args.get("event_id", type=int)
    available_events = Event.query.order_by(Event.name).all() if current_user.is_super_admin else []
    if not current_user.is_super_admin:
        if not current_user.event_id:
            abort(403)
        requested_event_id = current_user.event_id
        available_events = Event.query.filter_by(id=current_user.event_id).all()

    active_event: Optional[Event] = None
    if requested_event_id:
        active_event = Event.query.get_or_404(requested_event_id)
    elif available_events:
        active_event = available_events[0]

    event_form = EventCreateForm()
    upload_form = CsvUploadForm()
    guest_form = GuestForm()
    action_form = GuestActionForm()
    upload_form.event_id.choices = [(event.id, event.name) for event in available_events if event]

    if current_user.is_super_admin and event_form.submit_event.data and event_form.validate_on_submit():
        existing_event = Event.query.filter(
            (Event.name == event_form.name.data) | (Event.code_prefix == event_form.code_prefix.data.upper())
        ).first()
        if existing_event:
            flash("Event-Name oder Prefix ist bereits vergeben.", "danger")
            return redirect(url_for("admin.admin_dashboard", event_id=existing_event.id))
        new_event = Event(
            name=event_form.name.data,
            code_prefix=event_form.code_prefix.data.upper(),
            description=event_form.description.data,
            event_date=event_form.event_date.data,
            invitation_text=event_form.invitation_text.data,
            background_image_url=event_form.background_image_url.data or None,
        )
        db.session.add(new_event)
        db.session.commit()
        flash("Event erfolgreich angelegt", "success")
        return redirect(url_for("admin.admin_dashboard", event_id=new_event.id))

    if upload_form.submit.data and upload_form.validate_on_submit():
        target_event_id = upload_form.event_id.data
        _require_event_access(target_event_id)
        target_event = Event.query.get_or_404(target_event_id)

        stream = upload_form.file.data.stream.read().decode("utf-8").splitlines()
        reader = csv.DictReader(stream)
        required_headers = {
            "name",
            "nachname",
            "kategorie",
            "max_persons",
            "invite_code",
            "email",
            "telephone",
            "notify_admin",
        }
        if set(reader.fieldnames or []) != required_headers:
            flash(
                "CSV-Header stimmen nicht: erwartet name, nachname, kategorie, max_persons, invite_code, email, telephone, notify_admin",
                "danger",
            )
            return redirect(url_for("admin.admin_dashboard", event_id=target_event_id))

        imported = 0
        errors = []
        for index, row in enumerate(reader, start=2):
            first_name = (row.get("name") or "").strip()
            last_name = (row.get("nachname") or "").strip() or None
            category = (row.get("kategorie") or "").strip()
            max_persons_raw = (row.get("max_persons") or "").strip()
            invite_code = (row.get("invite_code") or "").strip()
            email_value = (row.get("email") or "").strip() or None
            telephone = (row.get("telephone") or "").strip() or None
            notify_raw = (row.get("notify_admin") or "").strip().lower()

            if not first_name:
                errors.append(f"Zeile {index}: Name fehlt")
                continue
            if category not in ALLOWED_CATEGORIES:
                errors.append(f"Zeile {index}: Kategorie '{category}' ist nicht erlaubt")
                continue
            try:
                max_persons = int(max_persons_raw)
            except ValueError:
                errors.append(f"Zeile {index}: max_persons muss eine Zahl sein")
                continue
            if max_persons < 1:
                errors.append(f"Zeile {index}: max_persons muss >= 1 sein")
                continue
            normalized_code = _validate_invite_code_for_event(invite_code, target_event)
            if not normalized_code:
                errors.append(
                    f"Zeile {index}: Invite-Code ungültig oder Prefix passt nicht (erwartet {target_event.code_prefix})"
                )
                continue
            if email_value and not is_valid_email(email_value):
                errors.append(f"Zeile {index}: Ungültige E-Mail '{email_value}'")
                continue

            code_hash = hash_invite_code(normalized_code)
            existing_hash = Guest.query.filter_by(event_id=target_event.id, invite_code_hash=code_hash).first()
            if existing_hash:
                errors.append(f"Zeile {index}: Invite-Code bereits vergeben")
                continue

            notify_admin_value = notify_raw in {"1", "true", "yes", "ja", "y"}

            guest = Guest(
                event_id=target_event.id,
                first_name=first_name,
                last_name=last_name,
                category=category,
                max_persons=max_persons,
                invite_code_hash=code_hash,
                email=email_value,
                telephone=telephone,
                notify_admin=notify_admin_value,
            )
            db.session.add(guest)
            imported += 1
        if imported:
            db.session.commit()
        flash(f"{imported} Einträge für {target_event.name} importiert", "success")
        if errors:
            flash(f"{len(errors)} Zeilen übersprungen: " + "; ".join(errors), "danger")
        return redirect(url_for("admin.admin_dashboard", event_id=target_event_id))

    if guest_form.submit_guest.data and guest_form.validate_on_submit():
        if not active_event:
            flash("Bitte wähle zuerst ein Event aus.", "warning")
            return redirect(url_for("admin.admin_dashboard"))
        _require_event_access(active_event.id)
        normalized_code = _prepare_manual_invite_code(guest_form.invite_code.data, active_event)
        if not normalized_code:
            flash(
                f"Invite-Code muss 5 Zeichen enthalten und beginnt automatisch mit {active_event.code_prefix}.",
                "danger",
            )
        else:
            code_hash = hash_invite_code(normalized_code)
            if Guest.query.filter_by(event_id=active_event.id, invite_code_hash=code_hash).first():
                flash("Invite-Code bereits vergeben", "danger")
            else:
                guest = Guest(
                    event_id=active_event.id,
                    first_name=guest_form.first_name.data,
                    last_name=guest_form.last_name.data or None,
                    category=guest_form.category.data,
                    max_persons=guest_form.max_persons.data,
                    invite_code_hash=code_hash,
                    email=guest_form.email.data or None,
                    telephone=guest_form.telephone.data or None,
                    notify_admin=guest_form.notify_admin.data,
                )
                db.session.add(guest)
                db.session.commit()
                flash("Gast gespeichert", "success")
                return redirect(url_for("admin.admin_dashboard", event_id=active_event.id))

    guests: Iterable[Guest] = []
    stats = {"total": 0, "pax_yes": 0, "declined": 0, "open": 0}
    if active_event:
        guests = Guest.query.filter_by(event_id=active_event.id).order_by(Guest.first_name, Guest.last_name).all()
        stats["total"] = len(guests)
        stats["pax_yes"] = (
            db.session.query(db.func.coalesce(db.func.sum(Guest.confirmed_persons), 0))
            .filter_by(event_id=active_event.id, status="zusage")
            .scalar()
        )
        stats["declined"] = Guest.query.filter_by(event_id=active_event.id, status="absage").count()
        stats["open"] = Guest.query.filter(
            Guest.event_id == active_event.id, Guest.status.notin_(["zusage", "absage"])
        ).count()

    return render_template(
        "admin_dashboard.html",
        guests=guests,
        upload_form=upload_form,
        event_form=event_form,
        guest_form=guest_form,
        active_event=active_event,
        available_events=available_events,
        action_form=action_form,
        stats=stats,
    )


@admin_bp.route("/admin/event/<int:event_id>/template")
@login_required
def download_template(event_id: int) -> Response:
    """Generate and return a CSV template for guest imports."""

    _require_event_access(event_id)
    event = Event.query.get_or_404(event_id)
    template_path = "csv_template.csv"
    with open(template_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "name",
                "nachname",
                "kategorie",
                "max_persons",
                "invite_code",
                "email",
                "telephone",
                "notify_admin",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "name": "Max",
                "nachname": "Mustermann",
                "kategorie": ALLOWED_CATEGORIES[0],
                "max_persons": 2,
                "invite_code": f"{event.code_prefix}-ABCDE",
                "email": "optional@example.com",
                "telephone": "01234/56789",
                "notify_admin": True,
            }
        )
    return send_file(template_path, as_attachment=True)


@admin_bp.route("/admin/event/<int:event_id>/guest/<int:guest_id>/email", methods=["POST"])
@login_required
def send_guest_email(event_id: int, guest_id: int) -> Response:
    """Send an email invitation with PDF to a guest."""

    _require_event_access(event_id)
    guest = Guest.query.filter_by(id=guest_id, event_id=event_id).first_or_404()
    form = GuestActionForm()
    if not form.validate_on_submit() or form.action.data != "email":
        abort(400)
    if not guest.email:
        flash("Keine E-Mail-Adresse für diesen Gast hinterlegt.", "warning")
        return redirect(url_for("admin.admin_dashboard", event_id=event_id))

    invite_url = url_for("public.invite", event_id=event_id, code=guest.invite_code_hash, _external=True)
    pdf_bytes = build_invite_pdf(guest, guest.event, invite_url)
    sent = send_email(
        subject=f"Deine Einladung zu {guest.event.name}",
        recipients=[guest.email],
        html_body=(
            f"<p>Hallo {guest.first_name},</p>"
            f"<p>{guest.event.invitation_text}</p>"
            f"<p>Dein persönlicher Link: <a href='{invite_url}'>{invite_url}</a></p>"
        ),
        attachments=[(f"Einladung_{guest.first_name}.pdf", pdf_bytes)],
    )
    if sent:
        flash("E-Mail wurde versendet.", "success")
    else:
        flash("Mail-Versand ist nicht konfiguriert.", "warning")
    return redirect(url_for("admin.admin_dashboard", event_id=event_id))


@admin_bp.route("/admin/event/<int:event_id>/guest/<int:guest_id>/pdf")
@login_required
def download_guest_pdf(event_id: int, guest_id: int) -> Response:
    """Return a PDF invitation for the guest."""

    _require_event_access(event_id)
    guest = Guest.query.filter_by(id=guest_id, event_id=event_id).first_or_404()
    invite_url = url_for("public.invite", event_id=event_id, code=guest.invite_code_hash, _external=True)
    pdf_bytes = build_invite_pdf(guest, guest.event, invite_url)
    filename = f"Einladung_{guest.first_name}.pdf"
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name=filename)
