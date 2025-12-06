"""Main Flask application for secure party invitation management."""

import os  # Import os to access environment variables for configuration.
import csv  # Import csv to parse admin-uploaded guest seed files.
from datetime import datetime  # Import datetime for timestamping access logs.
from typing import Optional  # Import Optional for explicit type hints.

from dotenv import load_dotenv  # Import load_dotenv to read .env secrets safely.
from flask import (
    Flask,  # Flask core application class.
    render_template,  # Helper for rendering HTML templates.
    request,  # Access HTTP request data.
    redirect,  # Redirect users after form submissions.
    url_for,  # Build URLs for Flask routes.
    flash,  # Provide user feedback messages.
    session,  # Manage server-side session for login state.
    send_file,  # Allow admin to download CSV template.
    abort,  # Abort requests with proper HTTP status codes.
)
from flask_sqlalchemy import SQLAlchemy  # SQLAlchemy ORM for MariaDB access.
from flask_wtf import FlaskForm  # Flask-WTF base form with CSRF support.
from flask_login import (
    LoginManager,  # Login manager to protect admin routes.
    UserMixin,  # Mixin providing default user methods.
    login_user,  # Helper to mark a user as logged in.
    login_required,  # Decorator to enforce authentication.
    logout_user,  # Helper to log out the current user.
    current_user,  # Proxy to the current logged-in admin.
)
import pyotp  # PyOTP provides Time-based One-Time Password (TOTP) 2FA.
from werkzeug.security import generate_password_hash, check_password_hash  # Password hashing utilities.
from wtforms import (
    StringField,  # Text input for codes, names, and emails.
    IntegerField,  # Number input for person counts.
    SelectField,  # Dropdown for status selection.
    BooleanField,  # Checkbox to control admin notifications.
    PasswordField,  # Password input for admin authentication.
    SubmitField,  # Submit buttons for forms.
    FileField,  # File upload control for CSV import.
    TextAreaField,  # Multi-line input for event description.
)
from wtforms.validators import (
    DataRequired,  # Ensures field is provided.
    Length,  # Enforces field length limits.
    Regexp,  # Applies regex validation to prevent XSS and ensure shape.
    NumberRange,  # Ensures numbers fall within expected bounds.
    Email,  # Validates email addresses.
    Optional,  # Allows a field to be blank when status does not require it.
)
from flask_wtf.file import FileAllowed, FileRequired  # Validators for file uploads.

# Load environment variables from a .env file placed outside version control.
load_dotenv()

# Initialize the Flask application with secure defaults.
app = Flask(__name__)
# Configure the secret key exclusively through environment variables for CSRF and session protection.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
# Build the MariaDB connection string using environment-provided credentials to avoid hardcoding secrets.
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@"
    f"{os.environ.get('DB_HOST')}/{os.environ.get('DB_NAME')}"
)
# Enable SQL echo in development when requested for debugging SQL statements securely.
app.config["SQLALCHEMY_ECHO"] = os.environ.get("SQLALCHEMY_ECHO", "false").lower() == "true"
# Turn off modification tracking overhead since it is unnecessary for most applications.
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize SQLAlchemy ORM after app configuration is set.
db = SQLAlchemy(app)
# Configure Flask-Login to work with the Flask app.
login_manager = LoginManager(app)
# Define the login view for redirecting unauthenticated users to the admin login page.
login_manager.login_view = "admin_login"


class Event(db.Model):
    """Represents a tenant-specific event that isolates all guest and admin data."""

    id = db.Column(db.Integer, primary_key=True)  # Primary key identifying the event (tenant).
    name = db.Column(db.String(150), nullable=False, unique=True)  # Human-readable event title.
    description = db.Column(db.Text, nullable=True)  # Optional description for clarity in dashboards.

    # Relationship hooks to guest units and logs ensure cascading cleanup when an event is removed.
    guest_units = db.relationship("GuestUnit", backref="event", cascade="all, delete-orphan")
    access_logs = db.relationship("AccessLog", backref="event", cascade="all, delete-orphan")


class GuestUnit(db.Model):
    """Represents an invitation unit such as a family or couple, scoped to a single event."""

    __table_args__ = (
        db.UniqueConstraint("event_id", "invite_code", name="uq_event_code"),
    )  # Enforce code uniqueness inside each event at the database level.

    id = db.Column(db.Integer, primary_key=True)  # Primary key for internal reference.
    event_id = db.Column(
        db.Integer, db.ForeignKey("event.id"), nullable=False, index=True
    )  # Foreign key ensuring strict tenant scoping.
    name = db.Column(db.String(120), nullable=False)  # Human-readable name of the invitee unit.
    invite_code = db.Column(
        db.String(8), nullable=False, index=True
    )  # 8-char code unique within an event (enforced in validation logic).
    max_persons = db.Column(db.Integer, nullable=False)  # Maximum invited persons allowed for this unit.
    status = db.Column(db.String(20), default="safe_the_date", nullable=False)  # RSVP status.
    confirmed_persons = db.Column(db.Integer, default=0, nullable=False)  # Count of confirmed attendees.
    email = db.Column(db.String(255), nullable=True)  # Optional email for notifications.
    notify_admin = db.Column(db.Boolean, default=False, nullable=False)  # Flag for admin email alerts.
    notes = db.Column(db.Text, nullable=True)  # Optional notes or dietary needs captured from the form.

    # Relationship to access logs allows cascade deletion to keep database clean.
    accesses = db.relationship("AccessLog", backref="guest_unit", cascade="all, delete-orphan")


class AccessLog(db.Model):
    """Tracks each valid invite code access for analytics purposes and tenant isolation."""

    id = db.Column(db.Integer, primary_key=True)  # Primary key for log entry identification.
    event_id = db.Column(
        db.Integer, db.ForeignKey("event.id"), nullable=False, index=True
    )  # Event context to enforce strict tenant filtering.
    guest_unit_id = db.Column(
        db.Integer, db.ForeignKey("guest_unit.id"), nullable=False
    )  # Foreign key linking to the guest unit accessed.
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Timestamp of access.
    user_agent = db.Column(db.String(255), nullable=True)  # Optional browser info for insights.


class AdminUser(UserMixin, db.Model):
    """Admin user capable of accessing the dashboard with 2FA and tenant scoping."""

    id = db.Column(db.Integer, primary_key=True)  # Primary key for admin user.
    email = db.Column(db.String(255), unique=True, nullable=False)  # Unique admin email.
    password_hash = db.Column(db.String(255), nullable=False)  # BCrypt hash of the admin password.
    totp_secret = db.Column(db.String(32), nullable=False)  # Secret key used for TOTP validation.
    role = db.Column(
        db.String(20), nullable=False, default="event_admin"
    )  # Role differentiates super_admin and event_admin.
    event_id = db.Column(
        db.Integer, db.ForeignKey("event.id"), nullable=True
    )  # Event binding for event admins; null for super admins.

    # Relationship to event allows convenient access to the assigned tenant for event admins.
    event = db.relationship("Event")

    def verify_password(self, password: str) -> bool:
        """Check the provided password against the stored hash."""

        # Use Werkzeug's timing-safe password hash verification.
        return check_password_hash(self.password_hash, password)

    def generate_totp_uri(self) -> str:
        """Generate the TOTP provisioning URI for enrollment in authenticator apps."""

        # Build the otpauth URI using pyotp for compatibility with Google Authenticator.
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email, issuer_name="Secure Party Admin"
        )

    @property
    def is_super_admin(self) -> bool:
        """Convenience flag to check whether the admin controls all events."""

        # A super admin is identified by the dedicated role string.
        return self.role == "super_admin"


def create_admin_user(
    email: str, password: str, role: str = "event_admin", event: Optional[Event] = None
) -> AdminUser:
    """Utility helper to create a new admin with hashed password, random TOTP secret, and optional tenant binding."""

    # Generate a fresh TOTP secret for the admin account.
    secret = pyotp.random_base32()
    # Hash the provided password using Werkzeug for secure storage.
    password_hash = generate_password_hash(password)
    # Build the AdminUser instance with supplied email, hash, and secret.
    user = AdminUser(
        email=email,
        password_hash=password_hash,
        totp_secret=secret,
        role=role,
        event=event,
    )
    # Persist the admin to the database inside an application context.
    db.session.add(user)
    db.session.commit()
    # Return the created user so the caller can display the provisioning URI to enroll 2FA.
    return user


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login hook to reload a user from the session."""

    # Return the AdminUser instance by primary key or None if missing.
    return AdminUser.query.get(int(user_id))


class InviteForm(FlaskForm):
    """Form presented to guests based on their unique code."""

    status = SelectField(
        "Status",
        choices=[
            ("safe_the_date", "Save the Date"),
            ("zusage", "Zusage"),
            ("absage", "Absage"),
            ("unsicher", "Unsicher"),
        ],
        validators=[DataRequired()],
    )  # Dropdown for RSVP choices.
    confirmed_persons = IntegerField(
        "Anzahl der teilnehmenden Personen",
        validators=[Optional(), NumberRange(min=0, max=20)],
        default=0,
    )  # Dynamic field limited later based on invite code context.
    notes = StringField(
        "Besondere Hinweise",
        validators=[
            Optional(),
            Length(max=500),
            Regexp(r"^[\w\s.,!?'\-]*$", message="Ungültige Zeichen entdeckt."),
        ],
    )  # Free-text notes with regex to mitigate XSS attempts.
    submit = SubmitField("Antwort senden")  # Submission control.


class EventCreateForm(FlaskForm):
    """Form for super admins to create new events (tenants)."""

    name = StringField(
        "Event-Name",
        validators=[
            DataRequired(),
            Length(max=150),
            Regexp(r"^[\w\s.,!?'\-]+$", message="Bitte nur Standardzeichen verwenden."),
        ],
    )  # Event title constrained by regex to avoid XSS vectors.
    description = TextAreaField(
        "Beschreibung",
        validators=[Optional(), Length(max=1000)],
    )  # Optional descriptive text with length guard.
    submit_event = SubmitField("Event anlegen")  # Submission trigger for event creation.


class AdminLoginForm(FlaskForm):
    """First-step admin login form using email and password."""

    email = StringField(
        "E-Mail",
        validators=[DataRequired(), Email(), Length(max=255)],
    )  # Admin email input.
    password = PasswordField(
        "Passwort",
        validators=[DataRequired(), Length(min=8, max=128)],
    )  # Admin password input with length constraints.
    submit = SubmitField("Anmelden")  # Submit button for login.


class AdminTotpForm(FlaskForm):
    """Second-step admin login form for TOTP verification."""

    token = StringField(
        "TOTP-Code",
        validators=[DataRequired(), Regexp(r"^[0-9]{6}$", message="6-stelliger Code erforderlich")],
    )  # 6-digit token input from authenticator app.
    submit = SubmitField("Code prüfen")  # Submit button for TOTP verification.


class CsvUploadForm(FlaskForm):
    """Admin CSV upload form to seed or update guest units."""

    event_id = SelectField(
        "Event",
        coerce=int,
        validators=[DataRequired()],
    )  # Event selector to bind the upload to one tenant explicitly.
    file = FileField(
        "CSV-Datei",
        validators=[
            FileRequired(message="Bitte wählen Sie eine CSV-Datei aus."),
            FileAllowed(["csv"], "Nur CSV-Dateien sind erlaubt."),
        ],
    )  # Upload control restricted to CSV files.
    submit = SubmitField("Import starten")  # Trigger the CSV processing.


@app.before_request
def enforce_https_headers():
    """Add security headers to every response for basic hardening."""

    # Only set headers after the response object exists; Flask handles attachment transparently.
    @app.after_request
    def set_headers(response):
        # Instruct browsers to block content sniffing attacks.
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent the site from being embedded in iframes to mitigate clickjacking.
        response.headers["X-Frame-Options"] = "DENY"
        # Enable cross-site scripting filter in older browsers.
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


@app.route("/")
def index():
    """Landing page instructing users to use their invitation link."""

    # Render a simple landing page encouraging invitees to follow their personalized URL.
    return render_template("index.html")


@app.route("/event/<int:event_id>/invite/<code>", methods=["GET", "POST"])
def invite(event_id: int, code: str):
    """Display and process the invitation form for a specific invite code within an event."""

    # Look up the guest unit by the provided code and event; abort with 404 if not found to prevent cross-event leakage.
    guest = GuestUnit.query.filter_by(event_id=event_id, invite_code=code).first_or_404()

    # Record each valid code access for analytics and enforce tenant scoping on the log entry.
    access = AccessLog(
        event_id=event_id, guest_unit_id=guest.id, user_agent=request.headers.get("User-Agent")
    )
    db.session.add(access)
    db.session.commit()

    # Instantiate the form and dynamically cap the confirmed persons to the guest's allowance.
    form = InviteForm()
    form.confirmed_persons.validators = [
        Optional(),
        NumberRange(min=0, max=guest.max_persons, message="Bitte innerhalb der Einladung bleiben."),
    ]

    # Handle POST submissions with server-side validation.
    if form.validate_on_submit():
        # Update status and confirmed count only if appropriate for the chosen status.
        guest.status = form.status.data
        if form.status.data == "zusage":
            # When accepting, respect the maximum allowed persons.
            guest.confirmed_persons = min(form.confirmed_persons.data or 0, guest.max_persons)
        else:
            # For non-acceptance states, reset confirmed persons to zero.
            guest.confirmed_persons = 0
        # Persist any provided notes that passed regex validation.
        guest.notes = form.notes.data
        db.session.commit()
        # Provide user feedback and redirect to prevent duplicate submissions.
        flash("Danke für Ihre Rückmeldung!", "success")
        return redirect(url_for("invite", event_id=event_id, code=code))

    # Pre-fill form with current data for convenience on GET requests.
    if request.method == "GET":
        form.status.data = guest.status
        form.confirmed_persons.data = guest.confirmed_persons
        form.notes.data = guest.notes

    # Render the invitation template with guest-specific context.
    return render_template("invite.html", guest=guest, form=form)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """First step of admin authentication using email and password."""

    # Redirect already authenticated admins directly to the dashboard.
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard"))

    # Instantiate the login form for display and validation.
    form = AdminLoginForm()
    if form.validate_on_submit():
        # Find the admin user by email.
        user = AdminUser.query.filter_by(email=form.email.data).first()
        if user and user.verify_password(form.password.data):
            # Store user id in session to proceed to TOTP verification step.
            session["pre_2fa_user_id"] = user.id
            return redirect(url_for("admin_totp"))
        flash("Ungültige Zugangsdaten", "danger")
    # Render the login page when GET or validation fails.
    return render_template("admin_login.html", form=form)


@app.route("/admin/totp", methods=["GET", "POST"])
def admin_totp():
    """Second step of admin authentication verifying the TOTP code."""

    # Ensure a user passed the first authentication step.
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("admin_login"))

    # Load the user for whom we are verifying the TOTP token.
    user = AdminUser.query.get_or_404(user_id)
    form = AdminTotpForm()
    if form.validate_on_submit():
        # Validate the submitted 6-digit TOTP token.
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.token.data, valid_window=1):
            # Promote the user to fully logged-in state and clear the staging session.
            login_user(user)
            session.pop("pre_2fa_user_id", None)
            return redirect(url_for("admin_dashboard"))
        flash("TOTP-Code ungültig oder abgelaufen", "danger")
    # Render the TOTP challenge page.
    return render_template("admin_totp.html", form=form, provisioning_uri=user.generate_totp_uri())


@app.route("/admin/logout")
@login_required
def admin_logout():
    """Log the admin out and clear the session."""

    # Use Flask-Login to remove the user session and redirect to login.
    logout_user()
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    """Protected dashboard listing guest units per event, CSV imports, and event creation for super admins."""

    # Resolve the requested event context while enforcing role-based access control.
    requested_event_id = request.args.get("event_id", type=int)
    available_events = Event.query.order_by(Event.name).all() if current_user.is_super_admin else []
    if not current_user.is_super_admin:
        # Event admins are bound to a single event defined on their account.
        if not current_user.event_id:
            abort(403)
        requested_event_id = current_user.event_id
        available_events = Event.query.filter_by(id=current_user.event_id).all()

    # Select the active event either from the query parameter or the first available event for super admins.
    active_event = None
    if requested_event_id:
        active_event = Event.query.get_or_404(requested_event_id)
    elif available_events:
        active_event = available_events[0]

    # Prepare forms for event creation (super admin) and CSV upload (all admins within scope).
    event_form = EventCreateForm()
    upload_form = CsvUploadForm()
    upload_form.event_id.choices = [(event.id, event.name) for event in available_events if event]

    # Handle event creation only for super admins with valid submission.
    if current_user.is_super_admin and event_form.submit_event.data and event_form.validate_on_submit():
        new_event = Event(name=event_form.name.data, description=event_form.description.data)
        db.session.add(new_event)
        db.session.commit()
        flash("Event erfolgreich angelegt", "success")
        return redirect(url_for("admin_dashboard", event_id=new_event.id))

    # Handle CSV import when a valid event is selected and the form passes validation.
    if upload_form.submit.data and upload_form.validate_on_submit():
        target_event_id = upload_form.event_id.data
        # Enforce that event admins cannot switch events.
        if not current_user.is_super_admin and target_event_id != current_user.event_id:
            abort(403)
        target_event = Event.query.get_or_404(target_event_id)
        # Read the uploaded CSV securely using python's csv module.
        stream = upload_form.file.data.stream.read().decode("utf-8").splitlines()
        reader = csv.DictReader(stream)
        # Ensure the CSV includes expected headers.
        expected_headers = {"name", "invite_code", "max_persons", "email", "notify_admin"}
        if set(reader.fieldnames or []) != expected_headers:
            flash("CSV-Header stimmen nicht: erwartet name, invite_code, max_persons, email, notify_admin", "danger")
            return redirect(url_for("admin_dashboard", event_id=target_event_id))
        imported = 0
        for row in reader:
            # Validate invite code shape strictly with regex for eight alphanumeric characters to prevent cross-event collisions.
            if not row["invite_code"] or not Regexp(r"^[A-Za-z0-9]{8}$").regex.match(row["invite_code"]):
                continue
            # Upsert behavior: update existing unit scoped to the target event or create a new one.
            guest = GuestUnit.query.filter_by(event_id=target_event.id, invite_code=row["invite_code"]).first()
            if not guest:
                guest = GuestUnit(event_id=target_event.id, invite_code=row["invite_code"])
            guest.name = row["name"]
            guest.max_persons = int(row.get("max_persons") or 0)
            guest.email = row.get("email") or None
            guest.notify_admin = row.get("notify_admin", "false").lower() == "true"
            db.session.add(guest)
            imported += 1
        db.session.commit()
        flash(f"{imported} Einträge für {target_event.name} importiert oder aktualisiert", "success")
        return redirect(url_for("admin_dashboard", event_id=target_event_id))

    # Load guest units for the active event only to maintain strict data isolation.
    guests = (
        GuestUnit.query.filter_by(event_id=active_event.id).order_by(GuestUnit.name).all()
        if active_event
        else []
    )

    # Render the admin dashboard with guest data, available events, and both forms.
    return render_template(
        "admin_dashboard.html",
        guests=guests,
        upload_form=upload_form,
        event_form=event_form,
        active_event=active_event,
        available_events=available_events,
    )


@app.route("/admin/event/<int:event_id>/template")
@login_required
def download_template(event_id: int):
    """Provide a CSV template for admins to seed guest units within a specific event."""

    # Event admins can only download templates for their own event; super admins can target any event.
    if not current_user.is_super_admin and current_user.event_id != event_id:
        abort(403)

    # Create a simple CSV template in-memory for download.
    template_path = "csv_template.csv"
    with open(template_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile, fieldnames=["name", "invite_code", "max_persons", "email", "notify_admin"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "name": "Familie Müller",
                "invite_code": "ABC12345",
                "max_persons": 4,
                "email": "familie.mueller@example.com",
                "notify_admin": True,
            }
        )
    # Send the generated file to the admin for download.
    return send_file(template_path, as_attachment=True)


if __name__ == "__main__":
    # Run the Flask development server when executed directly (not for production on Strato).
    app.run(host="0.0.0.0", port=5000, debug=True)
"""
app.py
-------
Dieses Skript zeigt einen mandantenfähigen Flask-Anwendungsentwurf mit strenger Event-Isolation, 2FA-geschützten Admin-Dashboards, festen Status-Optionen und Beispielen für CSV-Import, Logging sowie serverseitige Validierung.
"""

# Standardbibliothek-Importe mit Kommentaren zur Funktion
from pathlib import Path  # Pfadoperationen für .env-Lokalisierung und WSGI-Kompatibilität
import re  # Reguläre Ausdrücke für serverseitige Validierung
from typing import Optional  # Typ-Hints für Klarheit bei Rückgabewerten

# Drittanbieter-Importe mit Kommentaren
from dotenv import load_dotenv  # Lädt Umgebungsvariablen aus .env ohne im Code Secrets zu speichern
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)  # Flask-Grundfunktionen für Routing, Sessions und Templates
from flask_sqlalchemy import SQLAlchemy  # ORM für MariaDB mit SQLAlchemy
from flask_wtf import CSRFProtect  # CSRF-Schutz für Formulare
from werkzeug.security import check_password_hash  # Sichere Passwortprüfung
import pyotp  # TOTP-Bibliothek für 2FA

# Globale Konstanten mit erklärenden Kommentaren
BASE_DIR = Path(__file__).resolve().parent  # Basisverzeichnis des Projekts
load_dotenv(BASE_DIR / ".env")  # Frühzeitiges Laden der Umgebungsvariablen

STATUS_OPTIONS = [
    "Safe the Date",
    "Zusage",
    "Absage",
    "Unsicher",
]  # Fester, zentral verwalteter Status-Satz für alle Events

# Flask-Applikation und Extensions initialisieren
app = Flask(__name__)  # Haupt-Flask-Objekt
app.config["SECRET_KEY"] = (
    # Geheimnis für Sessions/CSRF wird ausschließlich aus der Umgebung gelesen
    Path(BASE_DIR / ".env")
    and __import__("os").environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
)

# Datenbank-URI aus Umgebungsvariablen zusammensetzen, ohne Secrets im Code zu halten
_db_user = __import__("os").environ.get("DB_USER", "user")
_db_pass = __import__("os").environ.get("DB_PASSWORD", "pass")
_db_host = __import__("os").environ.get("DB_HOST", "localhost")
_db_port = __import__("os").environ.get("DB_PORT", "3306")
_db_name = __import__("os").environ.get("DB_NAME", "event_planner")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{_db_user}:{_db_pass}@{_db_host}:{_db_port}/{_db_name}"
)  # MariaDB/ MySQL-kompatible URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Overhead vermeiden

# CSRF-Schutz aktivieren, um Formularfälschungen zu verhindern
csrf = CSRFProtect(app)

# SQLAlchemy-Instanz erzeugen
_db = SQLAlchemy(app)


class Event(_db.Model):
    """Event-Tabelle mit festem Status-Satz und Zeitstempeln."""

    __tablename__ = "events"

    id = _db.Column(_db.BigInteger, primary_key=True)  # Primärschlüssel
    name = _db.Column(_db.String(255), nullable=False)  # Sichtbarer Name
    status = _db.Column(
        _db.Enum(*STATUS_OPTIONS), nullable=False, default="Safe the Date"
    )  # Event-Status aus fester Optionsmenge
    starts_at = _db.Column(_db.DateTime, nullable=True)  # Optionaler Startzeitpunkt
    ends_at = _db.Column(_db.DateTime, nullable=True)  # Optionaler Endzeitpunkt
    created_at = _db.Column(
        _db.DateTime, server_default=_db.func.current_timestamp()
    )  # Erstellungstimestamp
    updated_at = _db.Column(
        _db.DateTime,
        server_default=_db.func.current_timestamp(),
        onupdate=_db.func.current_timestamp(),
    )  # Änderungszeitpunkt

    guest_units = _db.relationship(
        "GuestUnit", backref="event", lazy=True, cascade="all, delete-orphan"
    )  # Beziehung zu Einladungseinheiten, strikt an event_id gebunden


class Admin(_db.Model):
    """Admin-Tabelle mit Rollen-Hierarchie und TOTP-Secret."""

    __tablename__ = "admins"

    id = _db.Column(_db.BigInteger, primary_key=True)  # Primärschlüssel
    email = _db.Column(_db.String(255), unique=True, nullable=False)  # Login-E-Mail
    password_hash = _db.Column(_db.String(255), nullable=False)  # Gehashter Passwort-Hash
    role = _db.Column(
        _db.Enum("super_admin", "event_admin"),
        nullable=False,
        default="event_admin",
    )  # Rollenwert
    assigned_event_id = _db.Column(
        _db.BigInteger, _db.ForeignKey("events.id"), nullable=True
    )  # Zugewiesenes Event (NULL für Super-Admins)
    totp_secret = _db.Column(_db.String(64), nullable=False)  # Secret für TOTP-2FA
    created_at = _db.Column(
        _db.DateTime, server_default=_db.func.current_timestamp()
    )  # Erstellungstimestamp
    updated_at = _db.Column(
        _db.DateTime,
        server_default=_db.func.current_timestamp(),
        onupdate=_db.func.current_timestamp(),
    )  # Änderungszeitpunkt


class GuestUnit(_db.Model):
    """Einladungseinheiten pro Event mit achtstelligem Code und Status."""

    __tablename__ = "guest_units"

    id = _db.Column(_db.BigInteger, primary_key=True)  # Primärschlüssel
    event_id = _db.Column(_db.BigInteger, _db.ForeignKey("events.id"), nullable=False)  # Mandantenbindung
    invite_code = _db.Column(_db.String(8), nullable=False)  # Achtstelliger Code
    max_attendees = _db.Column(_db.Integer, nullable=False, default=1)  # Max. Personen
    status = _db.Column(
        _db.Enum(*STATUS_OPTIONS), nullable=False, default="Safe the Date"
    )  # Fester Status-Satz
    final_attendees = _db.Column(_db.Integer, nullable=True)  # Finale Personenzahl
    primary_contact_name = _db.Column(_db.String(255), nullable=True)  # Optionaler Name
    notify_admin = _db.Column(_db.Boolean, nullable=False, default=False)  # E-Mail-Flag
    created_at = _db.Column(
        _db.DateTime, server_default=_db.func.current_timestamp()
    )  # Erstellungstimestamp
    updated_at = _db.Column(
        _db.DateTime,
        server_default=_db.func.current_timestamp(),
        onupdate=_db.func.current_timestamp(),
    )  # Änderungszeitpunkt

    __table_args__ = (
        _db.UniqueConstraint("event_id", "invite_code", name="uq_code_per_event"),
    )  # Code nur einmal pro Event zulässig


class AccessLog(_db.Model):
    """Tracking-Tabelle für jeden Seitenaufruf mit gültigem Code."""

    __tablename__ = "access_logs"

    id = _db.Column(_db.BigInteger, primary_key=True)  # Primärschlüssel
    event_id = _db.Column(_db.BigInteger, _db.ForeignKey("events.id"), nullable=False)  # Mandantenbindung
    invite_code = _db.Column(_db.String(8), nullable=False)  # Zugehöriger Code
    accessed_at = _db.Column(
        _db.DateTime, server_default=_db.func.current_timestamp()
    )  # Zeitstempel
    user_agent = _db.Column(_db.String(512), nullable=True)  # Optionaler User-Agent
    ip_address = _db.Column(_db.String(45), nullable=True)  # Optional: IPv4/IPv6


# Utility-Funktion zur Statusvalidierung mit Regex als serverseitiges XSS-Abwehrbeispiel
STATUS_REGEX = re.compile(r"^(Safe the Date|Zusage|Absage|Unsicher)$")


def validate_status(status: str) -> bool:
    """Prüft serverseitig, ob der Status einer erlaubten Option entspricht."""

    return bool(STATUS_REGEX.match(status))  # True nur bei exakt erlaubten Werten


# Beispielhafte Login-Logik mit Passwort- und TOTP-Prüfung
@app.route("/admin/login", methods=["POST"])
def admin_login():
    """Authentifiziert einen Admin mit Passwort und TOTP-Token."""

    # Eingabe aus Request auslesen
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    token = request.form.get("token", "")

    # Admin anhand der E-Mail laden
    admin: Optional[Admin] = Admin.query.filter_by(email=email).first()
    if not admin:
        return jsonify({"error": "Unknown user"}), 401  # Nutzer nicht gefunden

    # Passwort validieren (Hash-Vergleich)
    if not check_password_hash(admin.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401  # Falsches Passwort

    # TOTP-Token prüfen
    totp = pyotp.TOTP(admin.totp_secret)
    if not totp.verify(token):
        return jsonify({"error": "Invalid token"}), 401  # Ungültiges 2FA-Token

    # Session setzen und Rolle speichern
    session["admin_id"] = admin.id
    session["role"] = admin.role
    session["assigned_event_id"] = admin.assigned_event_id

    return jsonify({"message": "Login successful"})  # Erfolgreicher Login


# Helper zur Zugriffsbeschränkung basierend auf Rolle und Event-Zuordnung

def require_admin(role: str, event_id: Optional[int] = None) -> Optional[Admin]:
    """Gibt den Admin zurück, wenn Rolle passt und Event-Isolation erfüllt ist."""

    admin_id = session.get("admin_id")  # Session-Admin-ID lesen
    if not admin_id:
        return None  # Nicht eingeloggt

    admin: Optional[Admin] = Admin.query.get(admin_id)  # Admin laden
    if not admin:
        return None  # Ungültige Session

    # Rollen-Check erzwingen
    if admin.role != role:
        if not (admin.role == "super_admin" and role == "event_admin"):
            # Super-Admin darf Event-Admin-Routen nutzen, sonst verweigern
            return None

    # Event-Isolation: Event-Admins dürfen nur ihr eigenes Event sehen
    if admin.role == "event_admin" and event_id and admin.assigned_event_id != event_id:
        return None

    return admin  # Zugriff erlaubt


@app.route("/dashboard/event/<int:event_id>")
def event_dashboard(event_id: int):
    """Dashboard-Ansicht, strikt auf das Event des Admins gefiltert."""

    admin = require_admin("event_admin", event_id)
    if not admin:
        return jsonify({"error": "Unauthorized"}), 403

    # Query strikt mit event_id-Filter, um Datenisolierung sicherzustellen
    guests = GuestUnit.query.filter_by(event_id=event_id).all()
    return jsonify(
        {
            "event_id": event_id,
            "guest_count": len(guests),
            "guests": [g.invite_code for g in guests],
        }
    )


@app.route("/dashboard/super")
def super_dashboard():
    """Super-Admin-Übersicht über alle Events."""

    admin = require_admin("super_admin")
    if not admin:
        return jsonify({"error": "Unauthorized"}), 403

    events = Event.query.all()
    return jsonify({"events": [{"id": e.id, "name": e.name} for e in events]})


@app.route("/register/<int:event_id>/<code>", methods=["GET", "POST"])
def register(event_id: int, code: str):
    """Registrierungsformular mit dynamischer Felderzeugung auf Basis max_attendees."""

    # Einladungsdatensatz strikt per event_id und Code filtern
    guest = GuestUnit.query.filter_by(event_id=event_id, invite_code=code).first()
    if not guest:
        return jsonify({"error": "Invalid code"}), 404

    # Aufruf logging für Resonanzmessung
    log = AccessLog(
        event_id=event_id,
        invite_code=code,
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )
    _db.session.add(log)
    _db.session.commit()

    if request.method == "GET":
        # Dynamische Felder anhand max_attendees
        dynamic_fields = "".join(
            [f'<input name="guest_{i}" placeholder="Name {i+1}">' for i in range(guest.max_attendees)]
        )
        # Minimalistisches Template (würde in Jinja2-Template ausgelagert werden)
        return render_template_string(
            """
            <form method="post">
                <input name="status" placeholder="Status" required>
                {{fields|safe}}
                <button type="submit">Senden</button>
            </form>
            """,
            fields=dynamic_fields,
        )

    # Serverseitige Statusvalidierung per Regex
    status_value = request.form.get("status", "")
    if not validate_status(status_value):
        return jsonify({"error": "Invalid status"}), 400

    # Finale Personenzahl sicher aus Request lesen und auf Zahl prüfen
    attendee_values = [
        request.form.get(f"guest_{i}", "").strip()
        for i in range(guest.max_attendees)
        if request.form.get(f"guest_{i}")
    ]
    guest.final_attendees = len(attendee_values)
    guest.status = status_value

    _db.session.commit()

    return jsonify({"message": "Registration saved", "attendees": attendee_values})


@app.route("/admin/upload_csv/<int:event_id>", methods=["POST"])
def upload_csv(event_id: int):
    """Konzeptueller CSV-Import nur für Super-Admin, streng nach event_id."""

    admin = require_admin("super_admin")
    if not admin:
        return jsonify({"error": "Unauthorized"}), 403

    # CSV-Datei aus Request holen (Validierung der Dateiendung/Größe erforderlich)
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400

    # Beispielhafte Iteration (in Produktion: csv.DictReader nutzen, Encoding prüfen)
    for line in file.stream:  # Artifizielle Schleife für Demonstrationszwecke
        decoded = line.decode("utf-8").strip()
        invite_code, max_attendees, notify_flag = decoded.split(",")

        # Serverseitige Regex-Validierung des Codes (acht alphanumerische Zeichen)
        if not re.match(r"^[A-Z0-9]{8}$", invite_code):
            continue  # Ungültigen Datensatz überspringen

        # Eintrag erzeugen, strikt event_id setzen
        unit = GuestUnit(
            event_id=event_id,
            invite_code=invite_code,
            max_attendees=int(max_attendees),
            notify_admin=notify_flag.lower() == "true",
        )
        _db.session.add(unit)

    _db.session.commit()
    return jsonify({"message": "CSV processed"})


def csv_structure_hint() -> str:
    """Beschreibt die erwartete CSV-Struktur für Imports."""

    return "invite_code,max_attendees,notify_admin"


# Einstiegspunkt für lokale Entwicklung
if __name__ == "__main__":
    # App im Entwicklungsmodus starten (nicht für Produktion geeignet)
    app.run(debug=True)
