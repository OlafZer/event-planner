#!/usr/bin/env python3
import cgitb
cgitb.enable()

import sys
import os
from pathlib import Path
from wsgiref.handlers import CGIHandler

# 1. Pfad zum Projektverzeichnis (ein Ordner über cgi-bin)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
#print(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

# 2. Site-Packages aus dem venv hinzufügen
# Prüfe bitte kurz mit 'ls ~/einladung/venv/lib', ob es python3.11 oder 3.10 ist
# und passe die nächste Zeile ggf. an!
venv_site_packages = PROJECT_ROOT / "venv/lib/python3.11/site-packages"
if venv_site_packages.exists():
    sys.path.insert(0, str(venv_site_packages))

# 3. Umgebungsvariablen laden
from dotenv import load_dotenv
#print(f"Loading dotenv: {load_dotenv(PROJECT_ROOT / '.env')}")


# 4. Flask App importieren und via CGI starten
from webserver import app

# WICHTIG: Das hier macht den Unterschied für Strato CGI!
if __name__ == '__main__':
    CGIHandler().run(app)
