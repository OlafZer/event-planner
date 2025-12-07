"""Hilfsskript: Löscht die konfigurierte MySQL-Datenbank vollständig.

Verwendung:
    python -m scripts.drop_database

Voraussetzungen:
    - .env mit DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
    - Der DB-User benötigt DROP/CREATE-Berechtigungen
"""

import os
import re
import sys
from typing import Optional

import pymysql
from dotenv import load_dotenv


REQUIRED_ENV_VARS = ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")


def _load_env() -> None:
    """Lädt die .env-Datei, falls vorhanden."""

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


def _validate_db_name(db_name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", db_name):
        sys.exit("Ungültiger Datenbankname: nur Buchstaben, Zahlen und Unterstrich sind erlaubt.")
    return db_name


def drop_database(db_name: str) -> None:
    safe_name = _validate_db_name(db_name)
    with _connect(None) as connection, connection.cursor() as cursor:
        cursor.execute(f"DROP DATABASE IF EXISTS `{safe_name}`;")
    print(f"Datenbank '{safe_name}' wurde gelöscht (falls vorhanden).")


def main():
    _load_env()
    for key in REQUIRED_ENV_VARS:
        _env_or_exit(key)

    db_name = _validate_db_name(os.environ["DB_NAME"])
    print("WARNUNG: Diese Aktion löscht alle Daten unwiderruflich.")
    confirm = input(f"Zum Fortfahren bitte den Datenbanknamen '{db_name}' eingeben: ").strip()
    if confirm != db_name:
        sys.exit("Abgebrochen: Eingabe stimmt nicht mit dem Datenbanknamen überein.")

    drop_database(db_name)


if __name__ == "__main__":
    main()
