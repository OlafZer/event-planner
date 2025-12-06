"""Main Flask application for secure party invitation management."""

import os  # Import os to access environment variables for configuration.
import csv  # Import csv to parse admin-uploaded guest seed files.
from datetime import datetime  # Import datetime for timestamping access logs.
from typing import Optional as TypingOptional  # Alias Optional to avoid clashing with WTForms validator.

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
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import BooleanField, FileField, IntegerField, PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional as OptionalValidator

load_dotenv()

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

    salt = app.config.get("SECURITY_PASSWORD_SALT", "")
    value = f"{salt}:{code}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["SECURITY_PASSWORD_SALT"] = os.environ.get("SECURITY_PASSWORD_SALT", "")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@"
    f"{os.environ.get('DB_HOST')}/{os.environ.get('DB_NAME')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = os.environ.get("SQLALCHEMY_ECHO", "false").lower() == "true"


# Database

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "admin_login"


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)

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
    user_agent = db.Column(db.String(255), nullable=True)


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


# Forms


class AccessCodeForm(FlaskForm):
    """Simple landing form for guests to enter their 8-character invite code."""

    access_code = StringField(
        "Zugangscode",
        validators=[
            DataRequired(message="Bitte geben Sie Ihren Code ein."),
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
        guest = GuestUnit.query.filter_by(invite_code=code).first()
        if guest:
            return redirect(url_for("invite", event_id=guest.event_id, code=guest.invite_code))
        flash("Dieser Zugangscode wurde nicht gefunden. Bitte prüfen Sie Ihre Eingabe.", "danger")

    return render_template("index.html", form=form)


@app.route("/event/<int:event_id>/invite/<code>", methods=["GET", "POST"])
def invite(event_id: int, code: str):
    event = Event.query.get_or_404(event_id)
    code_hash = hash_invite_code(code)
    guest = Guest.query.filter_by(event_id=event.id, invite_code_hash=code_hash).first_or_404()

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
        flash("Danke für Ihre Rückmeldung!", "success")
        return redirect(url_for("invite", event_id=event_id, code=code))

    if request.method == "GET":
        form.status.data = getattr(guest, "status", "safe_the_date")
        form.confirmed_persons.data = getattr(guest, "confirmed_persons", 0)
        form.notes.data = getattr(guest, "notes", "")

    return render_template("invite.html", guest=guest, form=form)


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
    return render_template("admin_totp.html", form=form, provisioning_uri=user.generate_totp_uri())


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
    upload_form.event_id.choices = [(event.id, event.name) for event in available_events if event]

    if current_user.is_super_admin and event_form.submit_event.data and event_form.validate_on_submit():
        new_event = Event(name=event_form.name.data, description=event_form.description.data)
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
        for row in reader:
            first_name = (row.get("name") or "").strip()
            last_name = (row.get("nachname") or "").strip() or None
            category = (row.get("kategorie") or "").strip()
            max_persons_raw = (row.get("max_persons") or "").strip()
            invite_code = (row.get("invite_code") or "").strip()
            email_value = (row.get("email") or "").strip() or None
            telephone = (row.get("telephone") or "").strip() or None
            notify_raw = (row.get("notify_admin") or "").strip().lower()

            if not first_name:
                continue
            if category not in ALLOWED_CATEGORIES:
                continue
            try:
                max_persons = int(max_persons_raw)
            except ValueError:
                continue
            if max_persons < 1:
                continue
            if not invite_code:
                continue

            code_hash = hash_invite_code(invite_code)
            existing_hash = Guest.query.filter_by(event_id=target_event.id, invite_code_hash=code_hash).first()
            if existing_hash:
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
        db.session.commit()
        flash(f"{imported} Einträge für {target_event.name} importiert", "success")
        return redirect(url_for("admin_dashboard", event_id=target_event_id))

    if guest_form.submit_guest.data and guest_form.validate_on_submit():
        if not active_event:
            flash("Bitte zuerst ein Event auswählen", "warning")
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
    if active_event:
        guests = Guest.query.filter_by(event_id=active_event.id).order_by(Guest.first_name, Guest.last_name).all()

    return render_template(
        "admin_dashboard.html",
        guests=guests,
        upload_form=upload_form,
        event_form=event_form,
        guest_form=guest_form,
        active_event=active_event,
        available_events=available_events,
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
