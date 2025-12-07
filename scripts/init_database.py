"""Hilfsskript: Legt die MySQL-Datenbank an und importiert das Schema aus db_schema.sql.

Verwendung:
    python -m scripts.init_database

Voraussetzungen:
    - .env mit DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
    - Der DB-User benötigt CREATE/ALTER-Berechtigungen
    - db_schema.sql liegt im Projektwurzelverzeichnis
"""

import os
import re
import sys
from pathlib import Path
from typing import Iterable, Optional

import pymysql
from dotenv import load_dotenv


REQUIRED_ENV_VARS = ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / "db_schema.sql"


def _load_env() -> None:
    load_dotenv()


def _env_or_exit(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        sys.exit(f"Fehlende Umgebungsvariable: {key}")
    return value


def _connect(database: Optional[str] = None) -> pymysql.connections.Connection:
    return pymysql.connect(
        host=_env_or_exit("DB_HOST"),
        user=_env_or_exit("DB_USER"),
        password=_env_or_exit("DB_PASSWORD"),
        database=database,
        autocommit=True,
        charset="utf8mb4",
    )


def _split_statements(sql: str) -> Iterable[str]:
    for statement in sql.split(";"):
        cleaned = statement.strip()
        if cleaned:
            yield cleaned


def _validate_db_name(db_name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", db_name):
        sys.exit("Ungültiger Datenbankname: nur Buchstaben, Zahlen und Unterstrich sind erlaubt.")
    return db_name


def create_database(db_name: str) -> None:
    safe_name = _validate_db_name(db_name)
    with _connect(None) as connection, connection.cursor() as cursor:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{safe_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )
    print(f"Datenbank '{safe_name}' ist vorbereitet.")


def import_schema(db_name: str) -> None:
    if not SCHEMA_PATH.exists():
        sys.exit(f"Schema-Datei nicht gefunden: {SCHEMA_PATH}")

    sql_content = SCHEMA_PATH.read_text(encoding="utf-8")
    statements = list(_split_statements(sql_content))

    with _connect(_validate_db_name(db_name)) as connection, connection.cursor() as cursor:
        for stmt in statements:
            cursor.execute(stmt)
    print(f"Schema aus {SCHEMA_PATH.name} wurde importiert.")


def main():
    _load_env()
    for key in REQUIRED_ENV_VARS:
        _env_or_exit(key)

    db_name = _validate_db_name(os.environ["DB_NAME"])
    create_database(db_name)
    import_schema(db_name)


if __name__ == "__main__":
    main()
