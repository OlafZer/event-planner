"""Application configuration classes loaded from environment variables."""

from __future__ import annotations

import os
from typing import Type
from urllib.parse import quote_plus

from dotenv import load_dotenv


load_dotenv()


class BaseConfig:
    """Base configuration that loads values from environment variables."""

    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    SECURITY_PASSWORD_SALT: str = os.environ.get("SECURITY_PASSWORD_SALT", "")
    _db_host = os.environ.get("DB_HOST")
    _db_port = os.environ.get("DB_PORT") or "3306"
    _db_user = os.environ.get("DB_USER")
    _db_password = os.environ.get("DB_PASSWORD")
    _db_name = os.environ.get("DB_NAME")
    SQLALCHEMY_DATABASE_URI: str = (
        f"mysql+pymysql://{quote_plus(_db_user or '')}:{quote_plus(_db_password or '')}@{_db_host}:{_db_port}/{_db_name}"
        if _db_host
        else "sqlite:///event_planner.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = os.environ.get("SQLALCHEMY_ECHO", "false").lower() == "true"
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS: bool = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME: str | None = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD: str | None = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER: str | None = os.environ.get("MAIL_DEFAULT_SENDER")
    LOGO_URL: str = os.environ.get("LOGO_URL", "")


class DevelopmentConfig(BaseConfig):
    """Configuration for local development."""

    DEBUG: bool = True


class ProductionConfig(BaseConfig):
    """Configuration for production deployments."""

    DEBUG: bool = False


def get_config() -> Type[BaseConfig]:
    """Return the configuration class based on the FLASK_DEBUG flag for Flask 3.x."""

    load_dotenv()
    debug_value = os.environ.get("FLASK_DEBUG", "0").lower()
    if debug_value in {"1", "true", "yes", "on"}:
        return DevelopmentConfig
    return ProductionConfig
