"""Flask application factory and extension initialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

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
