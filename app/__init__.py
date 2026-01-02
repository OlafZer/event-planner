"""Flask application factory and extension initialization."""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Any
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from werkzeug.exceptions import HTTPException

from config import get_config


db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def create_app() -> Flask:
    """Create and configure the Flask application instance."""

    base_dir = Path(__file__).resolve().parent.parent
    template_dir = base_dir / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.config.from_object(get_config())
    _configure_logging(app)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "admin.admin_login"

    app.config.setdefault("MUSIC_REQUESTS_AVAILABLE", True)
    app.config.setdefault("MUSIC_REQUESTS_ERROR", None)

    from app.routes.admin import admin_bp
    from app.routes.public import public_bp
    from app.routes.music_admin import music_admin_bp
    from app.routes.music_public import music_public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(music_admin_bp)
    app.register_blueprint(music_public_bp)
    _register_error_handlers(app)

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


def _configure_logging(app: Flask) -> None:
    """Configure rotating file logging so CGI deployments capture tracebacks."""

    log_level_name = os.environ.get("APP_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    app.logger.setLevel(log_level)

    log_file = os.environ.get("APP_LOG_FILE") or os.environ.get("APP_LOG_PATH")
    default_log_path = Path(app.root_path).parent / "logs" / "flask-errors.log"
    log_path = Path(log_file) if log_file else default_log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    has_rotating_handler = any(isinstance(handler, RotatingFileHandler) for handler in app.logger.handlers)
    if not has_rotating_handler:
        handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
        handler.setLevel(log_level)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        app.logger.addHandler(handler)


def _register_error_handlers(app: Flask) -> None:
    """Add a catch-all error handler that logs a correlation ID."""

    @app.errorhandler(Exception)
    def _handle_exception(error: Exception):  # type: ignore[override]
        if isinstance(error, HTTPException):
            return error

        error_id = secrets.token_hex(8)
        logging.getLogger(__name__).exception("Unhandled exception [%s]", error_id)
        return render_template("error.html", error_id=error_id), 500
