#!/usr/bin/env python3
"""generate_invite_text.py

Erstellt eine Einladungstext-Datei (.txt) für einen einzelnen Gast.
Das Skript wird pro Gast einmal aufgerufen.

Singular/Plural wird automatisch gewählt:
  --max-persons 1  →  "du", "dich", "dir", "kannst du", "bist du"
  --max-persons 2+ →  "euch", "könnt ihr", "seid ihr"

Der Dateiname entspricht dem Cover-Bild, nur mit .txt statt .jpg:
  Herbert_und_Sybille_BOABC123.txt

Synopsis:
    python scripts/generate_invite_text.py \\
        --name "Herbert und Sybille" \\
        --nachname Marquardt \\
        --invite-code BOABC123 \\
        --invite-link https://www.example.de/... \\
        --max-persons 2 \\
        --output-dir ./einladungen

    # Oder Ausgabepfad direkt angeben:
    python scripts/generate_invite_text.py \\
        --name "Herbert und Sybille" --invite-code BOABC123 \\
        --output ./einladungen/Herbert_und_Sybille_BOABC123.txt

    # Bild-Pfad übergeben – .txt ersetzt die Endung automatisch:
    python scripts/generate_invite_text.py \\
        --name "Herbert und Sybille" --invite-code BOABC123 \\
        --image-path ./covers/Herbert_und_Sybille_BOABC123.jpg
"""

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Grammatik-Varianten  (Singular  vs.  Plural)
# ---------------------------------------------------------------------------
# Füge hier weitere Schlüssel hinzu, wenn der Text neue Formen braucht.
# Die Schlüssel werden als {platzhalter} im EINLADUNGSTEXT verwendet.

GRAMMATIK = {
    "singular": {
        "du_ihr":           "du",
        "dich_euch":        "dich",
        "dir_euch":         "dir",
        "mit_dir_euch":     "mit dir",
        "kannst_koennt":    "kannst du",
        "bist_seid":        "bist du",
        "bist_seid_ihr":    "bist du",
    },
    "plural": {
        "du_ihr":           "ihr",
        "dich_euch":        "euch",
        "dir_euch":         "euch",
        "mit_dir_euch":     "mit euch",
        "kannst_koennt":    "könnt ihr",
        "bist_seid":        "seid ihr",
        "bist_seid_ihr":    "seid ihr",
    },
}

# ---------------------------------------------------------------------------
# Einladungstext-Template
# ---------------------------------------------------------------------------
# Verfügbare Platzhalter:
#   {name}              Vorname(n)
#   {nachname}          Nachname
#   {full_name}         name + nachname
#   {invite_code}       Einladungscode
#   {invite_link}       Vollständiger Einladungslink
#
# Grammatik-Platzhalter (Singular/Plural automatisch):
#   {du_ihr}            du  /  ihr
#   {dich_euch}         dich  /  euch
#   {dir_euch}          dir  /  euch
#   {mit_dir_euch}      mit dir  /  mit euch
#   {kannst_koennt}     kannst du  /  könnt ihr
#   {bist_seid}         bist du  /  seid ihr
#   {bist_seid_ihr}     bist du  /  seid ihr  (Alias)

EINLADUNGSTEXT = """\
Hallo {name},

60 & 60 – ein guter Grund, das Leben zu feiern!

Das möchten wir gerne gemeinsam {mit_dir_euch} und laden herzlich am 22.05.2026 \
ab 18 Uhr in den Oberkellner in Greven ein.

Über eine Zusage freuen wir uns persönlich, telefonisch oder per Mail – \
am einfachsten aber über den Code {invite_code} unter www.zerfowski.de.
Dort {kannst_koennt} auch Musikwünsche hinterlassen und die Party mitgestalten.

Mit 60 haben wir schon alles, daher {bist_seid_ihr} Geschenkebefreit.
Wer dennoch eine kleine Freude machen möchte, darf gerne das kleine Sparschwein füttern.

Wir freuen uns über jede positive Rückmeldung und vor allem auf einen \
fröhlichen Abend {mit_dir_euch}.

Liebe Grüße
    Birgit und Olaf

Olaf-und-Birgit@zerfowski.de
Mobil Olaf:   01578 123456
Mobil Birgit: 0176 123456

Anmeldecode www.zerfowski.de: {invite_code}
Anmeldelink:  {invite_link}
"""

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def safe_filename(text: str) -> str:
    """Ersetzt dateiunsichere Zeichen durch Unterstriche."""
    return re.sub(r"[^\w]", "_", text, flags=re.UNICODE).strip("_")


def resolve_output_path(args: argparse.Namespace) -> Path:
    """
    Ermittelt den Ausgabepfad für die .txt-Datei.

    Priorität:
    1. --output  (direkter Pfad)
    2. --image-path  (Endung wird durch .txt ersetzt)
    3. Aus --name + --invite-code + --output-dir abgeleitet
    """
    if args.output:
        return Path(args.output)

    if args.image_path:
        img = Path(args.image_path)
        return img.with_suffix(".txt")

    stem = f"{safe_filename(args.name)}_{args.invite_code}"
    output_dir = Path(args.output_dir)
    return output_dir / f"{stem}.txt"


def build_placeholders(args: argparse.Namespace) -> dict:
    """Baut das Platzhalter-Dict aus CLI-Argumenten und Grammatik zusammen."""
    variante = "plural" if args.max_persons > 1 else "singular"
    grammatik = GRAMMATIK[variante]

    full_name = (
        f"{args.name} {args.nachname}".strip()
        if args.nachname
        else args.name
    )

    return {
        "name":         args.name,
        "nachname":     args.nachname or "",
        "full_name":    full_name,
        "invite_code":  args.invite_code,
        "invite_link":  args.invite_link or "",
        **grammatik,
    }


# ---------------------------------------------------------------------------
# Argument-Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="generate_invite_text.py",
        description="Einladungstext (.txt) für einen Gast erstellen.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ---- Gast-Daten ----
    gast = p.add_argument_group("Gast-Daten")
    gast.add_argument(
        "--name",
        required=True,
        metavar="VORNAME",
        help='Vorname(n) des Gastes, z. B. "Herbert und Sybille"',
    )
    gast.add_argument(
        "--nachname",
        default="",
        metavar="NACHNAME",
        help="Nachname (optional)",
    )
    gast.add_argument(
        "--invite-code",
        required=True,
        metavar="CODE",
        help="Persönlicher Einladungscode, z. B. BOABC123",
    )
    gast.add_argument(
        "--invite-link",
        default="",
        metavar="URL",
        help="Vollständiger Einladungslink (optional)",
    )
    gast.add_argument(
        "--max-persons",
        type=int,
        default=1,
        metavar="N",
        help="Anzahl eingeladener Personen. "
             "1 = Einzelperson (du/dich/dir), "
             "≥2 = Paar/Gruppe (ihr/euch/könnt ihr).  (Standard: 1)",
    )

    # ---- Ausgabe ----
    out = p.add_argument_group("Ausgabe")
    out.add_argument(
        "--output",
        metavar="DATEI.txt",
        help="Direkter Ausgabepfad.  Überschreibt --output-dir und --image-path.",
    )
    out.add_argument(
        "--image-path",
        metavar="DATEI.jpg",
        help="Pfad zum zugehörigen Cover-Bild.  "
             "Die .txt-Datei erhält denselben Namen, nur mit .txt-Endung.",
    )
    out.add_argument(
        "--output-dir",
        default=".",
        metavar="VERZEICHNIS",
        help="Ausgabe-Verzeichnis, wenn weder --output noch --image-path "
             "angegeben sind.  (Standard: aktuelles Verzeichnis)",
    )
    out.add_argument(
        "--print",
        action="store_true",
        dest="print_to_stdout",
        help="Text zusätzlich auf der Konsole ausgeben",
    )

    return p


# ---------------------------------------------------------------------------
# Hauptprogramm
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Ausgabepfad ermitteln
    output_path = resolve_output_path(args)

    # Ausgabe-Verzeichnis anlegen
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Platzhalter befüllen
    placeholders = build_placeholders(args)

    # Text rendern
    try:
        text = EINLADUNGSTEXT.format_map(placeholders)
    except KeyError as exc:
        sys.exit(f"Unbekannter Platzhalter im Template: {exc}")

    # Datei schreiben
    output_path.write_text(text, encoding="utf-8")
    print(f"Einladungstext gespeichert: {output_path}")

    # Optional: auch auf Konsole ausgeben
    if args.print_to_stdout:
        print()
        print(text)


if __name__ == "__main__":
    main()
