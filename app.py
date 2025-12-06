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
