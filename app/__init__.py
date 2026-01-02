"""Flask application factory and extension initialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError

from config import get_config


db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()


def create_app() -> Flask:
    """Create and configure the Flask application instance."""

    base_dir = Path(__file__).resolve().parent.parent
    template_dir = base_dir / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.config.from_object(get_config())

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    login_manager.login_view = "admin.admin_login"

    from app.routes.admin import admin_bp
    from app.routes.public import public_bp
    from app.routes.music_admin import music_admin_bp
    from app.routes.music_public import music_public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(music_admin_bp)
    app.register_blueprint(music_public_bp)

    _ensure_music_schema(app)

    @app.context_processor
    def inject_branding() -> dict[str, Any]:
        """Inject global template variables such as the branding logo URL."""

        return {"logo_url": app.config.get("LOGO_URL")}

    @app.after_request
    def set_security_headers(response: Any) -> Any:
        """Add basic security headers to every response."""

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    return app


def _ensure_music_schema(app: Flask) -> None:
    """Create missing music request schema pieces to avoid runtime errors."""

    from app.models import MusicRequest

    def _mark_unavailable(message: str) -> None:
        app.config["MUSIC_REQUESTS_AVAILABLE"] = False
        app.config["MUSIC_REQUESTS_ERROR"] = message

    app.config["MUSIC_REQUESTS_AVAILABLE"] = True
    app.config["MUSIC_REQUESTS_ERROR"] = None

    with app.app_context():
        try:
            inspector = inspect(db.engine)
            event_columns = {column["name"] for column in inspector.get_columns("events")}
        except SQLAlchemyError:
            app.logger.exception("Konnte Events-Schema nicht prüfen")
            _mark_unavailable("Datenbankverbindung fehlgeschlagen – bitte Strato-Datenbank prüfen.")
            return

        if "music_requests_enabled" not in event_columns:
            try:
                db.session.execute(
                    text("ALTER TABLE events ADD COLUMN music_requests_enabled BOOLEAN NOT NULL DEFAULT 0")
                )
                db.session.commit()
                app.logger.info("Spalte music_requests_enabled wurde ergänzt.")
            except SQLAlchemyError:
                db.session.rollback()
                app.logger.exception("Spalte music_requests_enabled konnte nicht ergänzt werden")
                _mark_unavailable(
                    "Musikwünsche sind nicht verfügbar, weil die Spalte music_requests_enabled fehlt. "
                    "Bitte Migration db_migration_music_requests.sql mit ALTER-Rechten ausführen."
                )
                return

        try:
            inspector = inspect(db.engine)
            has_music_table = inspector.has_table(MusicRequest.__tablename__)
        except SQLAlchemyError:
            app.logger.exception("Konnte music_requests-Tabelle nicht prüfen")
            _mark_unavailable("Datenbankverbindung fehlgeschlagen – bitte Strato-Datenbank prüfen.")
            return

        if not has_music_table:
            try:
                MusicRequest.__table__.create(bind=db.engine)
                app.logger.info("Tabelle music_requests wurde automatisch angelegt.")
            except SQLAlchemyError:
                app.logger.exception("Tabelle music_requests konnte nicht angelegt werden")
                _mark_unavailable(
                    "Musikwünsche sind deaktiviert, weil die Tabelle music_requests fehlt. "
                    "Bitte Migration db_migration_music_requests.sql mit CREATE-Rechten ausführen."
                )
                return
