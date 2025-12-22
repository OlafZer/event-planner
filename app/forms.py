"""WTForms classes for guest and admin interactions."""

from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from wtforms import (
    BooleanField,
    DateTimeLocalField,
    FileField,
    HiddenField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional, Regexp

from app.utils import ALLOWED_CATEGORIES, INVITE_CODE_PATTERN


class AccessCodeForm(FlaskForm):
    """Landing form for guests to enter their invite code."""

    access_code = StringField(
        "Zugangscode",
        validators=[
            DataRequired(message="Bitte gib deinen Code ein."),
            Regexp(INVITE_CODE_PATTERN, message="Bitte einen gültigen Code eingeben (z. B. SF-AB12C)."),
        ],
        render_kw={"placeholder": "Z. B. SF-AB12C", "maxlength": 8},
    )
    submit = SubmitField("Zugang prüfen")


class InviteForm(FlaskForm):
    """Guest RSVP form for updating attendance status."""

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
        validators=[Optional(), NumberRange(min=0, max=20)],
        default=0,
    )
    notes = StringField(
        "Besondere Hinweise",
        validators=[Optional(), Length(max=500)],
    )
    submit = SubmitField("Antwort senden")


class EventCreateForm(FlaskForm):
    """Form for creating new events as a super admin."""

    name = StringField("Event-Name", validators=[DataRequired(), Length(max=150)])
    code_prefix = StringField(
        "Event-Prefix",
        validators=[
            DataRequired(),
            Length(min=2, max=2),
            Regexp(r"^[A-Za-z]{2}$", message="Bitte genau zwei Buchstaben verwenden."),
        ],
        render_kw={"placeholder": "SF"},
    )
    description = TextAreaField("Beschreibung", validators=[Optional(), Length(max=1000)])
    event_date = DateTimeLocalField(
        "Event-Datum", format="%Y-%m-%dT%H:%M", validators=[DataRequired()], render_kw={"step": 900}
    )
    invitation_text = TextAreaField("Einladungstext", validators=[DataRequired(), Length(max=5000)])
    background_image_url = StringField(
        "Hintergrundbild-URL",
        validators=[Optional(), Length(max=512)],
        render_kw={"placeholder": "https://..."},
    )
    submit_event = SubmitField("Event anlegen")


class AdminLoginForm(FlaskForm):
    """Login form for the admin area."""

    email = StringField("E-Mail", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Passwort", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Anmelden")


class AdminTotpForm(FlaskForm):
    """Two-factor authentication form for admin login."""

    token = StringField("TOTP-Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Code prüfen")


class CsvUploadForm(FlaskForm):
    """CSV upload form for importing guest lists."""

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
    """Admin form for creating a guest manually."""

    first_name = StringField("Vorname", validators=[DataRequired(), Length(max=150)])
    last_name = StringField("Nachname", validators=[Optional(), Length(max=150)])
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
    invite_code = StringField(
        "Invite-Code (Klartext)",
        validators=[
            DataRequired(),
            Length(min=5, max=6),
            Regexp(r"^-?[A-Za-z0-9]{5}$", message="Code muss 5 Zeichen enthalten (z. B. -AB12C)."),
        ],
        render_kw={"maxlength": 6, "placeholder": "-AB12C"},
    )
    email = StringField("E-Mail (optional)", validators=[Optional(), Email(), Length(max=255)])
    telephone = StringField("Telefon", validators=[Optional(), Length(max=50)])
    notify_admin = BooleanField("Admin benachrichtigen", default=True)
    submit_guest = SubmitField("Gast speichern")


class GuestActionForm(FlaskForm):
    """Small helper form for admin actions per guest."""

    guest_id = HiddenField(validators=[DataRequired()])
    action = HiddenField(validators=[DataRequired()])
    submit_action = SubmitField("Aktion ausführen")
