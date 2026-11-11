#!/usr/bin/env python3
"""
correlate.py — Joint toutes les sources sur le chemin relatif et calcule le verdict.

Règle :
- détection ClamAV (hors heuristiques ci-dessous) -> INFECTED
- sinon, l'un des cas suivants -> SUSPICIOUS :
  * ClamAV : erreur de lecture, limite dépassée (Heuristics.Limits.Exceeded*),
    contenu chiffré (Heuristics.Encrypted*) — le fichier n'a pas été analysé ;
  * correspondance YARA, flag document, flag archive ;
  * fichier spécial ou illisible (special.json).
- sinon -> CLEAN
"""
from common import load_json, write_json

# Heuristiques ClamAV qui signifient « pas pu analyser », pas « malveillant »
CLAM_SUSPICIOUS_PREFIXES = ("Heuristics.Limits.Exceeded", "Heuristics.Encrypted")

files = load_json("files.json")
clamav = load_json("clamav.json")
yara = load_json("yara.json")
# Sorties optionnelles : tolérées absentes si une étape a été sautée
docs = load_json("docs.json", {})
archives = load_json("archives.json", {})
special = load_json("special.json", {})


def clam_level(result):
    if result == "OK":
        return None
    if result.startswith("ERREUR:") or result.startswith(CLAM_SUSPICIOUS_PREFIXES):
        return "SUSPICIOUS"
    return "INFECTED"


results = {}
for filepath in files:
    clam = clamav.get(filepath, "OK")
    yar = yara.get(filepath, [])
    doc_flags = docs.get(filepath, [])
    archive_flags = archives.get(filepath, [])
    special_flags = special.get(filepath, [])
    level = clam_level(clam)

    if level == "INFECTED":
        verdict = "INFECTED"
    elif level or yar or doc_flags or archive_flags or special_flags:
        # Une archive protégée, un fichier illisible ou un lien symbolique n'a
        # pas pu être vérifié -> suspect, pas « CLEAN » par défaut (cf
        # l'échantillon Mirai zippé/protégé passé inaperçu).
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    results[filepath] = {
        "clamav": clam,
        "yara": yar,
        "docs": doc_flags,
        "archives": archive_flags,
        "special": special_flags,
        "verdict": verdict
    }

write_json("correlation.json", results)

infected = sum(1 for v in results.values() if v["verdict"] == "INFECTED")
suspicious = sum(1 for v in results.values() if v["verdict"] == "SUSPICIOUS")
print(f"[+] Corrélation terminée : {infected} infecté(s), {suspicious} suspect(s)")
