#!/usr/bin/env python3
"""
common.py — Constantes et fonctions partagées par l'interface et les scripts
du pipeline. Les scripts sont lancés via `python3 /opt/station-blanche/bin/x.py`,
donc bin/ est dans sys.path et `import common` fonctionne sans configuration.
"""
import json
import os
import stat
import subprocess
from datetime import datetime

BASE = "/opt/station-blanche"
BIN = f"{BASE}/bin"
LOGS = f"{BASE}/logs"
MOUNT = f"{BASE}/mount"
REPORTS = f"{BASE}/reports"
QUARANTINE = f"{BASE}/quarantine"
YARA_RULES = f"{BASE}/yara_rules"
LOGO_PATH = f"{BASE}/icon/chu_rouen_logo.png"

# Palette extraite du logo CHU Rouen Normandie (interface + rapport)
CHU_BLUE_DARK  = "#005EAA"   # "CHU"
CHU_BLUE_LIGHT = "#03AFE7"   # "ROUEN" + trait
CHU_GRAY       = "#6E7178"   # "NORMANDIE"
CHU_BG         = "#F2F5F8"   # fond général, blanc cassé clinique
CHU_SURFACE    = "#FFFFFF"   # cartes / zones de contenu
CHU_BORDER     = "#DCE3EA"
CHU_TEXT       = "#26313C"
STATUS_GREEN   = "#2E9E5B"
STATUS_ORANGE  = "#DB9A2C"
STATUS_RED     = "#D64545"

# Au-delà, les signatures sont signalées comme trop anciennes
CLAMAV_MAX_AGE_DAYS = 7
YARA_MAX_AGE_DAYS = 30

# Dépôts de règles YARA clonés par l'installeur (nom affiché, dossier)
YARA_RULE_REPOS = [
    ("Neo23x0 signature-base", f"{YARA_RULES}/signature-base"),
    ("Elastic protections-artifacts", f"{YARA_RULES}/elastic-artifacts"),
]


# Flags de détecteurs purement informatifs : affichés dans le rapport, sans
# effet sur le verdict. Une macro lancée à l'ouverture est courante dans les
# classeurs métier ; seule la combinaison « lancée à l'ouverture + écrit un
# fichier ou lance un programme » (MACRO_SUSPICIOUS) rend le fichier suspect.
INFO_FLAGS = {"MACRO_AUTOEXEC"}


def rel_path(abs_path):
    """Chemin relatif au point de montage : clé de jointure de tout le pipeline."""
    return os.path.relpath(abs_path, MOUNT)


def is_regular_file(abs_path):
    """Vrai uniquement pour un fichier régulier, sans suivre les liens
    symboliques (un lien vers /dev/zero ou /etc/shadow ne doit jamais être lu)."""
    try:
        return stat.S_ISREG(os.lstat(abs_path).st_mode)
    except OSError:
        return False


def load_json(name, default=None):
    """Lit logs/<name>. Si `default` est fourni, un fichier absent le renvoie
    (sorties optionnelles) ; sinon l'absence lève une exception."""
    path = f"{LOGS}/{name}"
    if default is not None and not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def write_json(name, data):
    with open(f"{LOGS}/{name}", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def clamav_db_info():
    """Renvoie (texte de version, date de la base ou None).
    `clamscan --version` affiche par ex. « ClamAV 1.4.3/27820/Mon Nov 10 08:23:45 2026 »."""
    try:
        out = subprocess.run(["clamscan", "--version"], capture_output=True,
                             text=True, timeout=60).stdout.strip()
    except Exception as e:
        return f"inconnue ({e})", None
    parts = out.split("/")
    db_date = None
    if len(parts) >= 3:
        try:
            db_date = datetime.strptime(parts[2].strip(), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            pass
    return out or "inconnue", db_date


def yara_rules_info():
    """Renvoie [(nom, commit, date du commit ou None)] pour chaque dépôt de règles."""
    infos = []
    for name, path in YARA_RULE_REPOS:
        commit, date = "absent", None
        if os.path.isdir(f"{path}/.git"):
            try:
                out = subprocess.run(
                    ["git", "-C", path, "log", "-1", "--format=%h|%cs"],
                    capture_output=True, text=True, timeout=30
                ).stdout.strip()
                commit, _, date_str = out.partition("|")
                date = datetime.strptime(date_str, "%Y-%m-%d") if date_str else None
            except Exception:
                commit = "inconnu"
        infos.append((name, commit or "inconnu", date))
    return infos


def age_days(date):
    return (datetime.now() - date).days if date else None
