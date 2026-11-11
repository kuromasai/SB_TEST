#!/usr/bin/env python3
"""
quarantine.py — Copie les fichiers infectés/suspects en zone de quarantaine.
La clé USB est montée en lecture seule : aucune suppression n'est effectuée
sur la source. La suppression physique est à réaliser manuellement par
l'opérateur après validation du rapport.

Chaque scan a son propre dossier quarantine/<scan_id>/ (deux clés avec le même
chemin relatif ne s'écrasent plus). Les copies sont en lecture seule (0400),
sans bit d'exécution. Seuls les fichiers réguliers sont copiés : un lien
symbolique n'est jamais suivi (il pourrait désigner un fichier de l'hôte).
"""
import os
import shutil
from datetime import datetime

from common import MOUNT, QUARANTINE, is_regular_file, load_json, write_json

scan_info = load_json("scan_info.json", {})
scan_id = scan_info.get("scan_id") or datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
quar_dir = os.path.join(QUARANTINE, scan_id)

data = load_json("correlation.json")

quarantined = 0
warned = 0
errors = 0
not_copied = 0
summary = []

for filepath, info in data.items():
    verdict = info["verdict"]
    if verdict not in ("INFECTED", "SUSPICIOUS"):
        continue

    src = os.path.join(MOUNT, filepath)
    entry = {"file": filepath, "verdict": verdict,
             "clamav": info.get("clamav", ""),
             "yara": info.get("yara", []),
             "docs": info.get("docs", []),
             "archives": info.get("archives", []),
             "special": info.get("special", []),
             "quarantine_path": None}

    if not is_regular_file(src):
        # Lien symbolique, FIFO, dossier illisible… : rien à copier
        not_copied += 1
        print(f"  [~] Non copié (pas un fichier régulier) : {filepath}")
        summary.append(entry)
        continue

    dst = os.path.join(quar_dir, filepath)
    try:
        os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o400)
        entry["quarantine_path"] = dst
        summary.append(entry)
        if verdict == "INFECTED":
            quarantined += 1
            print(f"  [!] INFECTÉ copié en quarantaine : {filepath}")
        else:
            warned += 1
            reasons = info.get("yara", []) + info.get("docs", []) + info.get("archives", [])
            if info.get("clamav", "OK") != "OK":
                reasons.append(info["clamav"])
            print(f"  [?] SUSPECT copié en quarantaine : {filepath} — indicateurs : {', '.join(reasons)}")
    except Exception as e:
        errors += 1
        print(f"  [-] Erreur copie quarantaine ({filepath}) : {e}")

# Résumé quarantaine pour generate_report.py
write_json("quarantine.json", {
    "timestamp": datetime.now().isoformat(),
    "directory": quar_dir if (quarantined or warned) else None,
    "quarantined": quarantined,
    "suspicious": warned,
    "not_copied": not_copied,
    "errors": errors,
    "files": summary
})

print(f"[+] Quarantaine : {quarantined} infecté(s), {warned} suspect(s) copiés — suppression manuelle requise sur la clé")
if not_copied:
    print(f"  [~] {not_copied} élément(s) non copié(s) (fichiers spéciaux)")
if errors:
    print(f"  [-] {errors} erreur(s) lors des copies")
