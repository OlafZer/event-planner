"""Main Flask application for secure party invitation management."""

import os  # Import os to access environment variables for configuration.
import csv  # Import csv to parse admin-uploaded guest seed files.
import hashlib  # Import hashlib for invite code hashing.
from datetime import datetime  # Import datetime for timestamping access logs.
from io import BytesIO
from textwrap import wrap
from typing import Iterable, Optional as TypingOptional  # Alias Optional to avoid clashing with WTForms validator.

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_mail import Mail, Message
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
import pyotp
import segno
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import (
    BooleanField,
    DateTimeLocalField,
    FileField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
    HiddenField,
)
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional as OptionalValidator, Regexp

from reportlab.lib.pagesizes import A6
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

load_dotenv()

# Invite code hashing parameters
PBKDF2_ITERATIONS = 200_000


ALLOWED_CATEGORIES = (
    "Familie",
    "Nachbarn",
    "Freunde",
    "Arbeit Birgit",
    "Arbeit Olaf",
    "Volleyball",
    "Toastmasters",
)


def hash_invite_code(code: str) -> str:
    """
    Erzeugt einen deterministischen Hash für Invite-Codes.
    Nutzt SECURITY_PASSWORD_SALT aus der Flask-Konfiguration als Salt.
    Speichert nur den Hash in der DB, nicht den Klartext.
    """

    salt = app.config.get("SECURITY_PASSWORD_SALT", "").encode("utf-8")
    value = code.encode("utf-8")
    derived_key = hashlib.pbkdf2_hmac("sha256", value, salt, PBKDF2_ITERATIONS)
    return derived_key.hex()


def is_valid_email(value: str) -> bool:
    """Validates an email address string using WTForms' Email validator."""

    if not value:
        return True
    validator = Email()
    try:
        validator(None, type("Tmp", (), {"data": value, "raw_data": [value]}))
    except Exception:
        return False
    return True


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["SECURITY_PASSWORD_SALT"] = os.environ.get("SECURITY_PASSWORD_SALT", "")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@"
    f"{os.environ.get('DB_HOST')}/{os.environ.get('DB_NAME')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = os.environ.get("SQLALCHEMY_ECHO", "false").lower() == "true"
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")
app.config["LOGO_URL"] = os.environ.get("LOGO_URL", "")


# Database

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "admin_login"
mail = Mail(app)


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    event_date = db.Column(db.DateTime, nullable=False)
    invitation_text = db.Column(db.Text, nullable=False)
    background_image_url = db.Column(db.String(512), nullable=True)

    guests = db.relationship("Guest", backref="event", cascade="all, delete-orphan")


class Guest(db.Model):
    __tablename__ = "guests"

    id = db.Column(db.BigInteger, primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey("events.id"), nullable=False, index=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    max_persons = db.Column(db.Integer, nullable=False, default=1)
    invite_code_hash = db.Column(db.String(64), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=True)
    telephone = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="safe_the_date")
    confirmed_persons = db.Column(db.Integer, nullable=False, default=0)
    notes = db.Column(db.Text, nullable=True)
    notify_admin = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        server_onupdate=db.func.current_timestamp(),
    )

    accesses = db.relationship("AccessLog", backref="guest", cascade="all, delete-orphan")


class AccessLog(db.Model):
    __tablename__ = "access_log"

    id = db.Column(db.BigInteger, primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey("events.id"), nullable=False, index=True)
    guest_id = db.Column(db.BigInteger, db.ForeignKey("guests.id"), nullable=False)
    accessed_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_agent = db.Column(db.String(512), nullable=True)


class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin_user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="event_admin")
    event_id = db.Column(db.BigInteger, db.ForeignKey("events.id"), nullable=True)

    event = db.relationship("Event")

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def generate_totp_uri(self) -> str:
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email, issuer_name="Secure Party Admin"
        )

    @property
    def is_super_admin(self) -> bool:
        return self.role == "super_admin"


@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))


@app.context_processor
def inject_branding():
    return {"logo_url": app.config.get("LOGO_URL")}


def create_admin_user(
    email: str, password: str, role: str = "event_admin", event: TypingOptional[Event] = None
) -> AdminUser:
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


def _get_invite_hash(code: str) -> str:
    cleaned = (code or "").strip()
    if len(cleaned) == 64 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return cleaned.lower()
    return hash_invite_code(cleaned.upper())


def _get_guest_by_code(event_id: int, code: str) -> Guest:
    invite_hash = _get_invite_hash(code)
    return Guest.query.filter_by(event_id=event_id, invite_code_hash=invite_hash).first_or_404()


def _mail_configured() -> bool:
    return bool(app.config.get("MAIL_SERVER") and app.config.get("MAIL_DEFAULT_SENDER"))


def _send_email(subject: str, recipients: list[str], html_body: str, attachments: list[tuple[str, bytes]] | None = None):
    if not _mail_configured():
        return False
    message = Message(subject=subject, recipients=recipients, html=html_body)
    for filename, content in attachments or []:
        message.attach(filename=filename, content_type="application/pdf", data=content)
    mail.send(message)
    return True


def _generate_qr_png(data: str) -> BytesIO:
    qr = segno.make(data)
    buffer = BytesIO()
    qr.save(buffer, kind="png", scale=5)
    buffer.seek(0)
    return buffer


def _build_invite_pdf(guest: "Guest", event: Event, invite_url: str) -> bytes:
    qr_buffer = _generate_qr_png(invite_url)
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=A6)
    width, height = A6
    margin = 10 * mm

    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, height - margin - 10, event.name)

    c.setFont("Helvetica", 10)
    c.drawString(margin, height - margin - 28, f"Für: {guest.first_name} {guest.last_name or ''}".strip())
    c.drawString(margin, height - margin - 42, f"Wann: {event.event_date.strftime('%d.%m.%Y %H:%M Uhr')}")

    text_obj = c.beginText(margin, height - margin - 64)
    text_obj.setFont("Helvetica", 10)
    text_obj.textLine("Einladungstext:")
    for line in wrap(event.invitation_text or "", width=55):
        text_obj.textLine(line)
    c.drawText(text_obj)

    qr_size = 80
    c.drawImage(ImageReader(qr_buffer), width - qr_size - margin, margin, qr_size, qr_size, mask="auto")
    c.setFont("Helvetica", 8)
    c.drawString(margin, margin + qr_size + 4, "QR-Code scannen oder Link öffnen:")
    url_lines = wrap(invite_url, width=60)
    for idx, line in enumerate(url_lines):
        c.drawString(margin, margin + qr_size - 10 + (idx * 10), line)

    c.showPage()
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()


# Forms


class AccessCodeForm(FlaskForm):
    """Simple landing form for guests to enter their 8-character invite code."""

    access_code = StringField(
        "Zugangscode",
        validators=[
            DataRequired(message="Bitte gib deinen Code ein."),
            Regexp(r"^[A-Za-z0-9]{8}$", message="Bitte einen gültigen 8-stelligen Code eingeben."),
        ],
        render_kw={"placeholder": "Z. B. A1B2C3D4", "maxlength": 8},
    )  # Enforce the expected invite code shape right on the landing page.
    submit = SubmitField("Zugang prüfen")  # Trigger invite code lookup.


class InviteForm(FlaskForm):
    status = SelectField(
        "Status",
        choices=[
            ("safe_the_date", "Save the Date"),
            ("zusage", "Zusage"),
            ("absage", "Absage"),
            ("unsicher", "Unsicher"),
        ],
        validators=[DataRequired()],
    )
    confirmed_persons = IntegerField(
        "Anzahl der teilnehmenden Personen",
        validators=[OptionalValidator(), NumberRange(min=0, max=20)],
        default=0,
    )
    notes = StringField(
        "Besondere Hinweise",
        validators=[OptionalValidator(), Length(max=500)],
    )
    submit = SubmitField("Antwort senden")


class EventCreateForm(FlaskForm):
    name = StringField("Event-Name", validators=[DataRequired(), Length(max=150)])
    description = TextAreaField("Beschreibung", validators=[OptionalValidator(), Length(max=1000)])
    event_date = DateTimeLocalField(
        "Event-Datum", format="%Y-%m-%dT%H:%M", validators=[DataRequired()], render_kw={"step": 900}
    )
    invitation_text = TextAreaField("Einladungstext", validators=[DataRequired(), Length(max=5000)])
    background_image_url = StringField(
        "Hintergrundbild-URL",
        validators=[OptionalValidator(), Length(max=512)],
        render_kw={"placeholder": "https://..."},
    )
    submit_event = SubmitField("Event anlegen")


class AdminLoginForm(FlaskForm):
    email = StringField("E-Mail", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Passwort", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Anmelden")


class AdminTotpForm(FlaskForm):
    token = StringField("TOTP-Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Code prüfen")


class CsvUploadForm(FlaskForm):
    event_id = SelectField("Event", coerce=int, validators=[DataRequired()])
    file = FileField(
        "CSV-Datei",
        validators=[
            FileRequired(message="Bitte wählen Sie eine CSV-Datei aus."),
            FileAllowed(["csv"], "Nur CSV-Dateien sind erlaubt."),
        ],
    )
    submit = SubmitField("Import starten")


class GuestForm(FlaskForm):
    first_name = StringField("Vorname", validators=[DataRequired(), Length(max=150)])
    last_name = StringField("Nachname", validators=[OptionalValidator(), Length(max=150)])
    category = SelectField(
        "Kategorie",
        choices=[(c, c) for c in ALLOWED_CATEGORIES],
        validators=[DataRequired()],
    )
    max_persons = IntegerField(
        "Maximale Personen",
        validators=[DataRequired(), NumberRange(min=1)],
        default=1,
    )
    invite_code = StringField("Invite-Code (Klartext)", validators=[DataRequired(), Length(max=255)])
    email = StringField("E-Mail (optional)", validators=[OptionalValidator(), Email(), Length(max=255)])
    telephone = StringField("Telefon", validators=[OptionalValidator(), Length(max=50)])
    notify_admin = BooleanField("Admin benachrichtigen", default=True)
    submit_guest = SubmitField("Gast speichern")


class GuestActionForm(FlaskForm):
    guest_id = HiddenField(validators=[DataRequired()])
    action = HiddenField(validators=[DataRequired()])
    submit_action = SubmitField("Aktion ausführen")


# Routes


@app.after_request
def set_security_headers(response):
    """Add security headers to every response for basic hardening."""

    # Instruct browsers to block content sniffing attacks.
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent the site from being embedded in iframes to mitigate clickjacking.
    response.headers["X-Frame-Options"] = "DENY"
    # Enable cross-site scripting filter in older browsers.
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    """Landing page asking guests for their invite code and redirecting them to the event form."""

    form = AccessCodeForm()
    if form.validate_on_submit():
        code = form.access_code.data.strip().upper()
        code_hash = hash_invite_code(code)
        guest = Guest.query.filter_by(invite_code_hash=code_hash).first()
        if guest:
            return redirect(url_for("invite", event_id=guest.event_id, code=code))
        flash("Dieser Zugangscode wurde nicht gefunden. Bitte prüfe deine Eingabe.", "danger")

    return render_template("index.html", form=form)


@app.route("/event/<int:event_id>/invite/<code>", methods=["GET", "POST"])
def invite(event_id: int, code: str):
    event = Event.query.get_or_404(event_id)
    guest = _get_guest_by_code(event.id, code)

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
                _send_email(
                    subject=f"Status-Update von {guest.first_name} {guest.last_name or ''}",
                    recipients=recipients,
                    html_body=(
                        f"<p>{guest.first_name} {guest.last_name or ''} hat den Status auf <strong>{guest_status}</strong>"
                        f" gesetzt.</p><p>Personen: {confirmed}/{guest.max_persons}</p>"
                    ),
                )
        flash("Danke für deine Rückmeldung!", "success")
        return redirect(url_for("invite", event_id=event_id, code=code))

    if request.method == "GET":
        form.status.data = getattr(guest, "status", "safe_the_date")
        form.confirmed_persons.data = getattr(guest, "confirmed_persons", 0)
        form.notes.data = getattr(guest, "notes", "")

    return render_template(
        "invite.html",
        guest=guest,
        event=event,
        form=form,
        invite_url=url_for("invite", event_id=event.id, code=code, _external=True),
        background_image_url=event.background_image_url,
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard"))

    form = AdminLoginForm()
    if form.validate_on_submit():
        user = AdminUser.query.filter_by(email=form.email.data).first()
        if user and user.verify_password(form.password.data):
            session["pre_2fa_user_id"] = user.id
            return redirect(url_for("admin_totp"))
        flash("Ungültige Zugangsdaten", "danger")
    return render_template("admin_login.html", form=form)


@app.route("/login/admin", methods=["GET", "POST"])
def admin_login_alias():
    """Backward-compatible alias that forwards to the admin login page."""

    return admin_login()


@app.route("/admin/totp", methods=["GET", "POST"])
def admin_totp():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("admin_login"))

    user = AdminUser.query.get_or_404(user_id)
    form = AdminTotpForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.token.data, valid_window=1):
            login_user(user)
            session.pop("pre_2fa_user_id", None)
            return redirect(url_for("admin_dashboard"))
        flash("TOTP-Code ungültig oder abgelaufen", "danger")
    return render_template("admin_totp.html", form=form)


@app.route("/admin/logout")
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for("admin_login"))


def _require_event_access(event_id: int):
    if current_user.is_super_admin:
        return
    if not current_user.event_id or current_user.event_id != event_id:
        abort(403)


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard():
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
        new_event = Event(
            name=event_form.name.data,
            description=event_form.description.data,
            event_date=event_form.event_date.data,
            invitation_text=event_form.invitation_text.data,
            background_image_url=event_form.background_image_url.data or None,
        )
        db.session.add(new_event)
        db.session.commit()
        flash("Event erfolgreich angelegt", "success")
        return redirect(url_for("admin_dashboard", event_id=new_event.id))

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
            return redirect(url_for("admin_dashboard", event_id=target_event_id))

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
            if not invite_code:
                errors.append(f"Zeile {index}: Invite-Code fehlt")
                continue
            if email_value and not is_valid_email(email_value):
                errors.append(f"Zeile {index}: Ungültige E-Mail '{email_value}'")
                continue

            code_hash = hash_invite_code(invite_code)
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
        return redirect(url_for("admin_dashboard", event_id=target_event_id))

    if guest_form.submit_guest.data and guest_form.validate_on_submit():
        if not active_event:
            flash("Bitte wähle zuerst ein Event aus.", "warning")
            return redirect(url_for("admin_dashboard"))
        _require_event_access(active_event.id)
        code_hash = hash_invite_code(guest_form.invite_code.data)
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
            return redirect(url_for("admin_dashboard", event_id=active_event.id))

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


@app.route("/admin/event/<int:event_id>/template")
@login_required
def download_template(event_id: int):
    _require_event_access(event_id)
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
                "invite_code": "MEINCODE",
                "email": "optional@example.com",
                "telephone": "01234/56789",
                "notify_admin": True,
            }
        )
    return send_file(template_path, as_attachment=True)


@app.route("/admin/event/<int:event_id>/guest/<int:guest_id>/email", methods=["POST"])
@login_required
def send_guest_email(event_id: int, guest_id: int):
    _require_event_access(event_id)
    guest = Guest.query.filter_by(id=guest_id, event_id=event_id).first_or_404()
    form = GuestActionForm()
    if not form.validate_on_submit() or form.action.data != "email":
        abort(400)
    if not guest.email:
        flash("Keine E-Mail-Adresse für diesen Gast hinterlegt.", "warning")
        return redirect(url_for("admin_dashboard", event_id=event_id))

    invite_url = url_for("invite", event_id=event_id, code=guest.invite_code_hash, _external=True)
    pdf_bytes = _build_invite_pdf(guest, guest.event, invite_url)
    sent = _send_email(
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
    return redirect(url_for("admin_dashboard", event_id=event_id))


@app.route("/admin/event/<int:event_id>/guest/<int:guest_id>/pdf")
@login_required
def download_guest_pdf(event_id: int, guest_id: int):
    _require_event_access(event_id)
    guest = Guest.query.filter_by(id=guest_id, event_id=event_id).first_or_404()
    invite_url = url_for("invite", event_id=event_id, code=guest.invite_code_hash, _external=True)
    pdf_bytes = _build_invite_pdf(guest, guest.event, invite_url)
    filename = f"Einladung_{guest.first_name}.pdf"
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.route("/event/<int:event_id>/invite/<code>/qr")
def invite_qr(event_id: int, code: str):
    event = Event.query.get_or_404(event_id)
    _get_guest_by_code(event.id, code)
    invite_url = url_for("invite", event_id=event.id, code=code, _external=True)
    buffer = _generate_qr_png(invite_url)
    return send_file(buffer, mimetype="image/png")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
