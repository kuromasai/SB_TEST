#!/usr/bin/env python3
"""
parse_yara.py — Parse la sortie NDJSON de `yr scan` (YARA-X) et produit
logs/yara.json : { "chemin/relatif": ["regle_1", "regle_2"] }.

Format d'une ligne de logs/yara.ndjson (une par fichier qui matche) :
{"path": "/opt/station-blanche/mount/sub/fichier.exe", "rules": [{"identifier": "..."}]}
"""
import json
import os

from common import LOGS, rel_path, write_json

results = {}
ndjson_path = f"{LOGS}/yara.ndjson"

if os.path.exists(ndjson_path):
    with open(ndjson_path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            abs_path = entry.get("path", "")
            if not abs_path:
                continue
            rule_ids = [r.get("identifier", "?") for r in entry.get("rules", [])]
            if rule_ids:
                results[rel_path(abs_path)] = rule_ids

write_json("yara.json", results)

total_hits = sum(len(v) for v in results.values())
print(f"[+] Parsing YARA-X terminé : {len(results)} fichier(s) avec correspondance, {total_hits} règle(s) au total")
