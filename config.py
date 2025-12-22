"""Application configuration classes loaded from environment variables."""

from __future__ import annotations

import os
from typing import Type

from dotenv import load_dotenv


class BaseConfig:
    """Base configuration that loads values from environment variables."""

    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    SECURITY_PASSWORD_SALT: str = os.environ.get("SECURITY_PASSWORD_SALT", "")
    SQLALCHEMY_DATABASE_URI: str = (
        f"mysql+pymysql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@"
        f"{os.environ.get('DB_HOST')}/{os.environ.get('DB_NAME')}"
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
    """Return the configuration class based on the FLASK_ENV environment variable."""

    load_dotenv()
    environment = os.environ.get("FLASK_ENV", "production").lower()
    if environment == "development":
        return DevelopmentConfig
    return ProductionConfig
