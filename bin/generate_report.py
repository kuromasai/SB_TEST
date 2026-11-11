#!/usr/bin/env python3
"""
generate_report.py — Génère reports/report_<date>.html, le rapport réduit
affiché sur la station (QWebEngineView) : nom de la clé, date et heure du
scan, nombre de fichiers propres / suspects / infectés et liste des fichiers
avec leur verdict, pour que l'opérateur sache quoi supprimer de la clé.

Le détail des outils (ClamAV, YARA, documents, archives), les hashes, les
versions des signatures et les avertissements ne sont plus affichés ici : ils
sont envoyés au dashboard de traçabilité (export_scan.py), qui présente le
rapport complet.
"""
import os
import base64
import html as html_module
from datetime import datetime

from common import (
    LOGO_PATH, REPORTS,
    CHU_BLUE_DARK, CHU_GRAY, CHU_BG, CHU_SURFACE, CHU_BORDER, CHU_TEXT,
    STATUS_GREEN, STATUS_ORANGE, STATUS_RED,
    load_json,
)

esc = html_module.escape

os.makedirs(REPORTS, exist_ok=True)

correlation = load_json("correlation.json")
scan_info = load_json("scan_info.json", {})

infected = sum(1 for v in correlation.values() if v["verdict"] == "INFECTED")
suspicious = sum(1 for v in correlation.values() if v["verdict"] == "SUSPICIOUS")
clean = len(correlation) - infected - suspicious

# Nom de la clé : nom de volume, sinon fabricant + modèle, sinon périphérique
device = scan_info.get("device", {})
key_name = (device.get("label")
            or " ".join(x for x in (device.get("vendor"), device.get("model")) if x)
            or device.get("name")
            or "Clé inconnue")

try:
    scan_date = datetime.fromisoformat(scan_info["started"])
except (KeyError, ValueError):
    scan_date = datetime.now()

date_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
path = f"{REPORTS}/report_{date_file}.html"

verdict_colors = {"INFECTED": STATUS_RED, "SUSPICIOUS": STATUS_ORANGE, "CLEAN": STATUS_GREEN}
verdict_labels = {"INFECTED": "Infecté", "SUSPICIOUS": "Suspect", "CLEAN": "Propre"}
# Infectés puis suspects en tête de liste : ce sont eux que l'opérateur supprime
verdict_order = {"INFECTED": 0, "SUSPICIOUS": 1, "CLEAN": 2}

# Logo encodé en base64 pour un rendu fiable en file:// (indépendant du navigateur)
logo_html = ""
if os.path.exists(LOGO_PATH):
    with open(LOGO_PATH, "rb") as f:
        logo_b64 = base64.b64encode(f.read()).decode("ascii")
    logo_html = f'<img src="data:image/png;base64,{logo_b64}" alt="CHU Rouen Normandie" class="logo">'

rows = ""
for filepath, v in sorted(correlation.items(),
                          key=lambda item: (verdict_order.get(item[1]["verdict"], 3), item[0])):
    color = verdict_colors.get(v["verdict"], CHU_TEXT)
    label = verdict_labels.get(v["verdict"], v["verdict"])
    rows += f"""
    <tr>
        <td>{esc(filepath)}</td>
        <td><span class="verdict-pill" style="color:{color};border-color:{color}">{esc(label)}</span></td>
    </tr>"""
if not rows:
    rows = '<tr><td colspan="2">Aucun fichier sur la clé.</td></tr>'

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
        h2 {{
            font-size: 11px;
            font-weight: 600;
            color: {CHU_GRAY};
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin: 28px 0 10px 0;
        }}
        .summary {{ display: flex; gap: 14px; flex-wrap: wrap; }}
        .stat {{
            background: {CHU_SURFACE};
            border: 1px solid {CHU_BORDER};
            border-radius: 8px;
            padding: 14px 22px;
            min-width: 120px;
        }}
        .stat .value {{ font-size: 1.6em; font-weight: 600; color: {CHU_TEXT}; }}
        .stat .value.text {{ font-size: 1.15em; }}
        .stat .label {{
            font-size: 11px;
            color: {CHU_GRAY};
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 2px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: {CHU_SURFACE};
            border: 1px solid {CHU_BORDER};
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
        td:last-child {{ width: 110px; }}
        tr:last-child td {{ border-bottom: none; }}
        .verdict-pill {{
            display: inline-block;
            padding: 2px 10px;
            border: 1px solid;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
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
        <h1>Station Blanche — Rapport d'analyse</h1>
    </header>

    <div class="summary">
        <div class="stat">
            <div class="value text">{esc(key_name)}</div>
            <div class="label">Clé</div>
        </div>
        <div class="stat">
            <div class="value text">{scan_date:%d/%m/%Y %H:%M:%S}</div>
            <div class="label">Date du scan</div>
        </div>
        <div class="stat">
            <div class="value" style="color:{STATUS_GREEN}">{clean}</div>
            <div class="label">Propres</div>
        </div>
        <div class="stat">
            <div class="value" style="color:{STATUS_ORANGE}">{suspicious}</div>
            <div class="label">Suspects</div>
        </div>
        <div class="stat">
            <div class="value" style="color:{STATUS_RED}">{infected}</div>
            <div class="label">Infectés</div>
        </div>
    </div>

    <h2>Fichiers</h2>
    <table>
        <tr><th>Fichier</th><th>État</th></tr>
        {rows}
    </table>

    <footer>Rapport généré automatiquement par Station Blanche — CHU Rouen Normandie</footer>
</body>
</html>"""

with open(path, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"[✓] Rapport généré : {path}")
