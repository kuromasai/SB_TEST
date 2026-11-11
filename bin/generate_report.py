#!/usr/bin/env python3
"""
generate_report.py — Génère reports/report_<date>.html à partir des JSON du
pipeline. Le rapport est affiché dans l'interface (QWebEngineView) ; il
n'est plus ouvert dans un navigateur externe (qui tournait en root).
"""
import os
import socket
import base64
import html as html_module
from datetime import datetime

from common import (
    LOGO_PATH, REPORTS, CLAMAV_MAX_AGE_DAYS, YARA_MAX_AGE_DAYS,
    CHU_BLUE_DARK, CHU_GRAY, CHU_BG, CHU_SURFACE, CHU_BORDER, CHU_TEXT,
    STATUS_GREEN, STATUS_ORANGE, STATUS_RED,
    INFO_FLAGS, load_json, clamav_db_info, yara_rules_info, age_days,
)

esc = html_module.escape

os.makedirs(REPORTS, exist_ok=True)

files = load_json("files.json")
correlation = load_json("correlation.json")
scan_info = load_json("scan_info.json", {})
quarantine = load_json("quarantine.json", {})

total_files = len(files)
infected = sum(1 for v in correlation.values() if v["verdict"] == "INFECTED")
suspicious = sum(1 for v in correlation.values() if v["verdict"] == "SUSPICIOUS")

status_labels = {
    "INFECTED": "INFECTÉ",
    "SUSPICIOUS": "SUSPECT",
    "CLEAN": "PROPRE",
}

if infected:
    status = "INFECTED"
    status_color = STATUS_RED
elif suspicious:
    status = "SUSPICIOUS"
    status_color = STATUS_ORANGE
else:
    status = "CLEAN"
    status_color = STATUS_GREEN

status_label = status_labels[status]

now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
date_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
path = f"{REPORTS}/report_{date_file}.html"

verdict_colors = {
    "INFECTED": STATUS_RED,
    "SUSPICIOUS": STATUS_ORANGE,
    "CLEAN": STATUS_GREEN
}
verdict_labels = {
    "INFECTED": "Infecté",
    "SUSPICIOUS": "Suspect",
    "CLEAN": "Propre"
}

# Logo encodé en base64 pour un rendu fiable en file:// (indépendant du navigateur)
logo_html = ""
if os.path.exists(LOGO_PATH):
    with open(LOGO_PATH, "rb") as f:
        logo_b64 = base64.b64encode(f.read()).decode("ascii")
    logo_html = f'<img src="data:image/png;base64,{logo_b64}" alt="CHU Rouen Normandie" class="logo">'

rows = ""
for filepath, v in correlation.items():
    color = verdict_colors.get(v["verdict"], "#000")
    safe_path = esc(filepath)
    safe_clam = esc(v["clamav"])
    safe_yara = esc(", ".join(v["yara"]))
    # Les flags informatifs (sans effet sur le verdict) sont marqués comme tels
    safe_docs = esc(", ".join(f"{d} (info)" if d in INFO_FLAGS else d for d in v.get("docs", [])))
    safe_archives = esc(", ".join(v.get("archives", []) + v.get("special", [])))
    safe_verdict = esc(verdict_labels.get(v["verdict"], v["verdict"]))
    rows += f"""
    <tr>
        <td>{safe_path}</td>
        <td>{safe_clam}</td>
        <td>{safe_yara if safe_yara else "—"}</td>
        <td>{safe_docs if safe_docs else "—"}</td>
        <td>{safe_archives if safe_archives else "—"}</td>
        <td><span class="verdict-pill" style="color:{color};border-color:{color}">{safe_verdict}</span></td>
    </tr>"""

# ---------------------------------------------------------------------------
# Traçabilité : clé analysée, opérateur, station, version des signatures
# ---------------------------------------------------------------------------
warnings = []

clam_version, clam_date = clamav_db_info()
clam_age = age_days(clam_date)
if clam_age is None:
    warnings.append("Date de la base ClamAV inconnue : fraîcheur des signatures non vérifiable.")
elif clam_age > CLAMAV_MAX_AGE_DAYS:
    warnings.append(f"Base ClamAV datant de {clam_age} jours (seuil : {CLAMAV_MAX_AGE_DAYS} jours).")

yara_lines = []
for name, commit, date in yara_rules_info():
    age = age_days(date)
    date_txt = date.strftime("%d/%m/%Y") if date else "date inconnue"
    yara_lines.append(f"{name} : {commit} ({date_txt})")
    if age is not None and age > YARA_MAX_AGE_DAYS:
        warnings.append(f"Règles YARA « {name} » datant de {age} jours (seuil : {YARA_MAX_AGE_DAYS} jours).")

device = scan_info.get("device", {})
partitions = scan_info.get("disk_partitions", [])
if len(partitions) > 1:
    warnings.append(
        f"La clé contient {len(partitions)} partitions ({', '.join(partitions)}) : "
        f"seule {device.get('name', '?')} a été analysée dans ce rapport."
    )
if quarantine.get("errors"):
    warnings.append(f"{quarantine['errors']} fichier(s) n'ont pas pu être copiés en quarantaine.")


def info_row(label, value):
    return f"<tr><th>{esc(label)}</th><td>{esc(str(value)) if value else '—'}</td></tr>"


device_desc = " ".join(x for x in (device.get("vendor"), device.get("model")) if x)
info_rows = "".join([
    info_row("Date de l'analyse", now),
    info_row("Périphérique", device.get("name")),
    info_row("Fabricant / modèle", device_desc),
    info_row("Numéro de série", device.get("serial")),
    info_row("Nom de volume", device.get("label")),
    info_row("Système de fichiers", device.get("fstype")),
    info_row("Taille", device.get("size")),
    info_row("Opérateur", scan_info.get("operator")),
    info_row("Station", socket.gethostname()),
    info_row("Moteur ClamAV utilisé", scan_info.get("clamav_engine")),
    info_row("Base ClamAV", clam_version),
    info_row("Règles YARA", " · ".join(yara_lines)),
    info_row("Dossier de quarantaine", quarantine.get("directory")),
])

warnings_html = ""
if warnings:
    items = "".join(f"<li>{esc(w)}</li>" for w in warnings)
    warnings_html = f'<div class="warnings"><strong>Avertissements</strong><ul>{items}</ul></div>'

# Fichiers que les outils n'ont pas pu analyser (en tout ou partie)
UNANALYZED_MARKERS = ("ERREUR:", "Heuristics.Limits.Exceeded", "Heuristics.Encrypted",
                      "_PARSE_ERROR", "_READ_ERROR", "ARCHIVE_", "FICHIER_", "DOSSIER_")
unanalyzed_rows = ""
for filepath, v in correlation.items():
    reasons = [v["clamav"]] + v.get("docs", []) + v.get("archives", []) + v.get("special", [])
    reasons = [r for r in reasons if any(m in r for m in UNANALYZED_MARKERS)]
    if reasons:
        unanalyzed_rows += f"<tr><td>{esc(filepath)}</td><td>{esc(', '.join(reasons))}</td></tr>"
unanalyzed_section = ""
if unanalyzed_rows:
    unanalyzed_section = f"""
    <h2>Fichiers non analysés ou partiellement analysés</h2>
    <table>
        <tr><th>Fichier</th><th>Raison</th></tr>
        {unanalyzed_rows}
    </table>"""

# Hash recap pour traçabilité forensique
hash_section = ""
hashes = load_json("hashes.json", {})
if hashes:
    hash_rows = "".join(
        f"<tr><td>{esc(fp)}</td><td><code>{esc(h)}</code></td></tr>"
        for fp, h in hashes.items()
    )
    hash_section = f"""
    <h2>Hashes SHA-256</h2>
    <table>
        <tr><th>Fichier</th><th>SHA-256</th></tr>
        {hash_rows}
    </table>"""

html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Station Blanche – Rapport {date_file}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'IBM Plex Sans', 'Segoe UI', Arial, sans-serif;
            background: {CHU_BG};
            color: {CHU_TEXT};
            margin: 0;
            padding: 32px 40px;
        }}

        header {{
            display: flex;
            align-items: center;
            gap: 16px;
            padding-bottom: 16px;
            border-bottom: 1px solid {CHU_BORDER};
            margin-bottom: 24px;
        }}
        header .logo {{ height: 40px; }}
        header h1 {{
            font-size: 20px;
            font-weight: 600;
            color: {CHU_BLUE_DARK};
            margin: 0;
            letter-spacing: 0.3px;
        }}
        header .subtitle {{
            font-size: 11px;
            color: {CHU_GRAY};
            margin-top: 2px;
        }}

        h2 {{
            font-size: 11px;
            font-weight: 600;
            color: {CHU_GRAY};
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin: 28px 0 10px 0;
        }}

        .summary {{
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
        }}
        .stat {{
            background: {CHU_SURFACE};
            border: 1px solid {CHU_BORDER};
            border-radius: 8px;
            padding: 14px 22px;
            min-width: 120px;
        }}
        .stat .value {{
            font-size: 1.6em;
            font-weight: 600;
            color: {CHU_TEXT};
        }}
        .stat .label {{
            font-size: 11px;
            color: {CHU_GRAY};
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 2px;
        }}
        .stat.verdict {{
            border-color: {status_color};
            border-width: 1px;
        }}
        .stat.verdict .value {{ color: {status_color}; }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 4px;
            background: {CHU_SURFACE};
            border: 1px solid {CHU_BORDER};
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: {CHU_BG};
            color: {CHU_GRAY};
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid {CHU_BORDER};
        }}
        td {{
            padding: 9px 12px;
            border-bottom: 1px solid {CHU_BORDER};
            font-size: 13px;
            word-break: break-all;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: {CHU_BG}; }}

        .verdict-pill {{
            display: inline-block;
            padding: 2px 10px;
            border: 1px solid;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}

        code {{
            font-family: 'IBM Plex Mono', 'Consolas', Monospace;
            font-size: 0.8em;
            color: {CHU_GRAY};
        }}

        table.info th {{
            width: 220px;
            border-bottom: 1px solid {CHU_BORDER};
        }}
        table.info td {{ word-break: break-word; }}

        .warnings {{
            margin-top: 18px;
            background: {CHU_SURFACE};
            border: 1px solid {STATUS_ORANGE};
            border-radius: 8px;
            padding: 12px 18px;
            font-size: 13px;
            color: {CHU_TEXT};
        }}
        .warnings strong {{ color: {STATUS_ORANGE}; }}
        .warnings ul {{ margin: 6px 0 0 0; padding-left: 18px; }}

        footer {{
            margin-top: 32px;
            padding-top: 12px;
            border-top: 1px solid {CHU_BORDER};
            font-size: 11px;
            color: {CHU_GRAY};
        }}
    </style>
</head>
<body>
    <header>
        {logo_html}
        <div>
            <h1>Station Blanche — Rapport d'analyse</h1>
            
        </div>
    </header>

    <div class="summary">
        <div class="stat verdict">
            <div class="value">{status_label}</div>
            <div class="label">Verdict global</div>
        </div>
        <div class="stat">
            <div class="value">{total_files}</div>
            <div class="label">Fichiers analysés</div>
        </div>
        <div class="stat">
            <div class="value" style="color:{STATUS_RED}">{infected}</div>
            <div class="label">Infectés</div>
        </div>
        <div class="stat">
            <div class="value" style="color:{STATUS_ORANGE}">{suspicious}</div>
            <div class="label">Suspects</div>
        </div>
    </div>

    {warnings_html}

    <h2>Informations d'analyse</h2>
    <table class="info">
        {info_rows}
    </table>

    <h2>Détail des fichiers</h2>
    <table>
        <tr>
            <th>Fichier</th>
            <th>ClamAV</th>
            <th>YARA-X</th>
            <th>Documents (Office/PDF)</th>
            <th>Archives / fichiers spéciaux</th>
            <th>Verdict</th>
        </tr>
        {rows}
    </table>

    {unanalyzed_section}

    {hash_section}

    <footer>Rapport généré automatiquement par Station Blanche — CHU Rouen Normandie</footer>
</body>
</html>"""

with open(path, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"[✓] Rapport généré : {path}")
for w in warnings:
    print(f"[!] {w}")
