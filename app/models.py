"""Database models for the invitation application."""

from __future__ import annotations

from typing import Optional

import pyotp
from flask_login import UserMixin
from werkzeug.security import check_password_hash

from app import db


class Event(db.Model):
    """Event model describing a single invitation event."""

    __tablename__ = "events"

    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    code_prefix = db.Column(db.String(2), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    event_date = db.Column(db.DateTime, nullable=False)
    invitation_text = db.Column(db.Text, nullable=False)
    background_image_url = db.Column(db.String(512), nullable=True)

    guests = db.relationship("Guest", backref="event", cascade="all, delete-orphan")


class Guest(db.Model):
    """Guest model storing invitees and their status."""

    __tablename__ = "guests"

    id = db.Column(db.BigInteger, primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey("events.id"), nullable=False, index=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    max_persons = db.Column(db.Integer, nullable=False, default=1)
    invite_code_hash = db.Column(db.String(64), nullable=False, unique=True)
    invite_code_plain = db.Column(db.String(8), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    telephone = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="save_the_date")
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
    """Access log entries for guest invite form visits."""

    __tablename__ = "access_log"

    id = db.Column(db.BigInteger, primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey("events.id"), nullable=False, index=True)
    guest_id = db.Column(db.BigInteger, db.ForeignKey("guests.id"), nullable=False)
    accessed_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_agent = db.Column(db.String(512), nullable=True)


class AdminUser(UserMixin, db.Model):
    """Administrative user who manages events and guests."""

    __tablename__ = "admin_user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="event_admin")
    event_id = db.Column(db.BigInteger, db.ForeignKey("events.id"), nullable=True)

    event = db.relationship("Event")

    def verify_password(self, password: str) -> bool:
        """Return True when the provided password matches the stored hash."""

        return check_password_hash(self.password_hash, password)

    def generate_totp_uri(self) -> str:
        """Return a provisioning URI for configuring TOTP in authenticator apps."""

        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email, issuer_name="Secure Party Admin"
        )

    @property
    def is_super_admin(self) -> bool:
        """Return True if the admin user has global super admin permissions."""

        return self.role == "super_admin"


def get_event_by_prefix(prefix: str) -> Optional[Event]:
    """Return the event that matches the given code prefix."""

    return Event.query.filter_by(code_prefix=prefix).first()
