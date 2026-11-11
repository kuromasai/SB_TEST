#!/usr/bin/env python3
"""
export_scan.py — Prépare l'envoi du scan au dashboard de traçabilité.

Rassemble les JSON du pipeline (scan_info, correlation, hashes, quarantine),
les versions des signatures et la durée du scan dans un seul document, écrit
dans spool/pending/<scan_id>.json.gz. L'envoi réseau est fait à part par
sync_dashboard.py (service systemd station-blanche-sync), déclenché ici sans
attendre : ce script ne touche jamais au réseau et ne bloque pas le scan.

Appelé en fin de pipeline avec --statut TERMINE, ou par l'interface avec
--statut ERREUR / ANNULE quand le scan n'est pas allé au bout (on garde
alors une trace du branchement de la clé et de ce qui a déjà été analysé).

Seules des métadonnées sont envoyées (chemins, hashes, verdicts, indicateurs) :
les fichiers mis en quarantaine ne quittent jamais la station.
"""
import argparse
import gzip
import json
import os
import subprocess
import sys
from datetime import datetime

from common import (
    CLAMAV_MAX_AGE_DAYS, YARA_MAX_AGE_DAYS, INFO_FLAGS, PAYLOAD_FORMAT,
    SPOOL_PENDING, load_json, signatures_info, station_name,
)

parser = argparse.ArgumentParser()
parser.add_argument("--statut", choices=("TERMINE", "ERREUR", "ANNULE"), default="TERMINE")
parser.add_argument("--message", default="")
args = parser.parse_args()

scan_info = load_json("scan_info.json", {})
scan_id = scan_info.get("scan_id")
if not scan_id:
    print("[!] scan_info.json absent : rien à envoyer au dashboard")
    sys.exit(0)

correlation = load_json("correlation.json", {})
hashes = load_json("hashes.json", {})
quarantine = load_json("quarantine.json", {})
signatures = signatures_info()

finished = datetime.now()
try:
    duration = round((finished - datetime.fromisoformat(scan_info["started"])).total_seconds(), 1)
except (KeyError, ValueError):
    duration = None

# ---------------------------------------------------------------------------
# Avertissements (auparavant affichés dans le rapport de la station)
# ---------------------------------------------------------------------------
warnings = []


def age_from_iso(value):
    try:
        return (datetime.now() - datetime.fromisoformat(value)).days
    except (TypeError, ValueError):
        return None


clam_age = age_from_iso(signatures["clamav"]["db_date"])
if clam_age is None:
    warnings.append("Date de la base ClamAV inconnue : fraîcheur des signatures non vérifiable.")
elif clam_age > CLAMAV_MAX_AGE_DAYS:
    warnings.append(f"Base ClamAV datant de {clam_age} jours (seuil : {CLAMAV_MAX_AGE_DAYS} jours).")
for repo in signatures["yara"]:
    age = age_from_iso(repo["date"])
    if age is not None and age > YARA_MAX_AGE_DAYS:
        warnings.append(f"Règles YARA « {repo['name']} » datant de {age} jours (seuil : {YARA_MAX_AGE_DAYS} jours).")

device = scan_info.get("device", {})
partitions = scan_info.get("disk_partitions", [])
if len(partitions) > 1:
    warnings.append(
        f"La clé contient {len(partitions)} partitions ({', '.join(partitions)}) : "
        f"seule {device.get('name', '?')} a été analysée dans ce scan."
    )
if quarantine.get("errors"):
    warnings.append(f"{quarantine['errors']} fichier(s) n'ont pas pu être copiés en quarantaine.")
if args.statut != "TERMINE" and correlation:
    warnings.append("Scan interrompu : les résultats ci-dessous peuvent être incomplets.")

# ---------------------------------------------------------------------------
# Fichiers : verdict et indicateurs de chaque détecteur, joints sur le chemin
# ---------------------------------------------------------------------------
quarantine_paths = {e["file"]: e.get("quarantine_path") for e in quarantine.get("files", [])}

files = []
if correlation:
    for path, info in correlation.items():
        files.append({
            "path": path,
            "sha256": hashes.get(path, ""),
            "verdict": info.get("verdict", "CLEAN"),
            "clamav": info.get("clamav", "OK"),
            "yara": info.get("yara", []),
            "docs": info.get("docs", []),
            "archives": info.get("archives", []),
            "special": info.get("special", []),
            "quarantine_path": quarantine_paths.get(path),
        })
else:
    # Scan interrompu avant la corrélation : on garde au moins l'inventaire
    for path, sha in hashes.items():
        files.append({"path": path, "sha256": sha, "verdict": "NON_ANALYSE",
                      "clamav": "", "yara": [], "docs": [], "archives": [],
                      "special": [], "quarantine_path": None})

payload = {
    "format": PAYLOAD_FORMAT,
    "station": station_name(),
    "scan_id": scan_id,
    "status": args.statut,
    "message": args.message,
    "started": scan_info.get("started"),
    "finished": finished.isoformat(),
    "duration_s": duration,
    "operator": scan_info.get("operator"),
    "device": device,
    "disk_partitions": partitions,
    "clamav_engine": scan_info.get("clamav_engine"),
    "signatures": signatures,
    "warnings": warnings,
    "info_flags": sorted(INFO_FLAGS),
    "quarantine_dir": quarantine.get("directory"),
    "files": files,
}

# Écriture atomique : sync_dashboard.py ne doit jamais lire un fichier à moitié écrit
os.makedirs(SPOOL_PENDING, mode=0o700, exist_ok=True)
dest = os.path.join(SPOOL_PENDING, f"{scan_id}.json.gz")
tmp = os.path.join(SPOOL_PENDING, f".{scan_id}.json.gz.tmp")
with gzip.open(tmp, "wt", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False)
os.replace(tmp, dest)
print(f"[+] Scan mis en file d'envoi vers le dashboard ({len(files)} fichier(s))")

# Déclenche l'envoi sans l'attendre (--no-block) ; sinon le timer s'en charge
try:
    ret = subprocess.run(["systemctl", "start", "--no-block", "station-blanche-sync.service"],
                         capture_output=True, timeout=10).returncode
    if ret != 0:
        print("[~] Service station-blanche-sync indisponible : envoi au prochain passage du timer")
except Exception as e:
    print(f"[~] Envoi immédiat non déclenché ({e}) : il partira au prochain passage du timer")
