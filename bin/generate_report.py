#!/usr/bin/env python3
import json
import os
import subprocess
import base64
import html as html_module
from datetime import datetime

BASE = "/opt/station-blanche"
LOGS = f"{BASE}/logs"
REPORTS = f"{BASE}/reports"
LOGO_PATH = f"{BASE}/icon/chu_rouen_logo.png"

# Palette CHU Rouen Normandie — reprise à l'identique de l'interface (station_blanche.py)
CHU_BLUE_DARK  = "#005EAA"
CHU_BLUE_LIGHT = "#03AFE7"
CHU_GRAY       = "#6E7178"
CHU_BG         = "#F2F5F8"
CHU_SURFACE    = "#FFFFFF"
CHU_BORDER     = "#DCE3EA"
CHU_TEXT       = "#26313C"
STATUS_GREEN   = "#2E9E5B"
STATUS_ORANGE  = "#DB9A2C"
STATUS_RED     = "#D64545"

os.makedirs(REPORTS, exist_ok=True)

with open(f"{LOGS}/files.json") as f:
    files = json.load(f)

with open(f"{LOGS}/correlation.json") as f:
    correlation = json.load(f)

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
    safe_path = html_module.escape(filepath)
    safe_clam = html_module.escape(v["clamav"])
    safe_yara = html_module.escape(", ".join(v["yara"]))
    safe_docs = html_module.escape(", ".join(v.get("docs", [])))
    safe_archives = html_module.escape(", ".join(v.get("archives", [])))
    safe_verdict = html_module.escape(verdict_labels.get(v["verdict"], v["verdict"]))
    rows += f"""
    <tr>
        <td>{safe_path}</td>
        <td>{safe_clam}</td>
        <td>{safe_yara if safe_yara else "—"}</td>
        <td>{safe_docs if safe_docs else "—"}</td>
        <td>{safe_archives if safe_archives else "—"}</td>
        <td><span class="verdict-pill" style="color:{color};border-color:{color}">{safe_verdict}</span></td>
    </tr>"""

# Hash recap pour traçabilité forensique
hash_section = ""
hash_file = f"{LOGS}/hashes.json"
if os.path.exists(hash_file):
    with open(hash_file) as f:
        hashes = json.load(f)
    hash_rows = "".join(
        f"<tr><td>{html_module.escape(fp)}</td><td><code>{html_module.escape(h)}</code></td></tr>"
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
            font-family: 'Segoe UI', Arial, sans-serif;
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
            font-family: 'Consolas', Monospace;
            font-size: 0.8em;
            color: {CHU_GRAY};
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

    <h2>Détail des fichiers</h2>
    <table>
        <tr>
            <th>Fichier</th>
            <th>ClamAV</th>
            <th>YARA-X</th>
            <th>Documents (Office/PDF)</th>
            <th>Archives</th>
            <th>Verdict</th>
        </tr>
        {rows}
    </table>

    {hash_section}

    <footer>Rapport généré automatiquement par Station Blanche — CHU Rouen Normandie</footer>
</body>
</html>"""

with open(path, "w") as f:
    f.write(html_content)

print(f"[✓] Rapport généré : {path}")

# Ouverture du rapport dans la session graphique de l'utilisateur réel (pas root)
real_user = os.environ.get("REAL_USER", "")
real_display = os.environ.get("REAL_DISPLAY", ":0")
real_xauthority = os.environ.get("REAL_XAUTHORITY", "")

if real_user and real_user != "root":
    env = os.environ.copy()
    env["DISPLAY"] = real_display
    env["XAUTHORITY"] = real_xauthority
    result = subprocess.run(
        ["sudo", "-u", real_user, "env",
         f"DISPLAY={real_display}",
         f"XAUTHORITY={real_xauthority}",
         "xdg-open", path],
        env=env
    )
    if result.returncode != 0:
        print(f"[!] Impossible d'ouvrir le rapport automatiquement : {path}")
else:
    # Fallback : lancé directement en root sans sudo, on tente quand même
    subprocess.run(["xdg-open", path])
