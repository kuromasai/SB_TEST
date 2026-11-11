#!/usr/bin/env python3
"""
parse_clamav.py — Parse logs/clamav.log (clamscan ou clamdscan) et produit
logs/clamav.json : { "chemin/relatif": "OK" | "<signature>" | "ERREUR:<message>" }.

Les lignes d'erreur (« Access denied », « lstat() failed »…) sont conservées :
un fichier que ClamAV n'a pas pu lire ne doit pas finir « OK » par défaut.
"""
from common import MOUNT, load_json, rel_path, write_json, LOGS

PREFIX = MOUNT + "/"
known_files = set(load_json("files.json"))


def split_line(line):
    """Sépare « <chemin>: <reste> ». Un nom de fichier peut contenir « : »,
    on prend donc la première coupure qui donne un chemin connu de l'inventaire."""
    idx = line.find(": ")
    first = idx
    while idx != -1:
        if rel_path(line[:idx]) in known_files:
            return rel_path(line[:idx]), line[idx + 2:]
        idx = line.find(": ", idx + 1)
    if first == -1:
        return None, None
    return rel_path(line[:first]), line[first + 2:]


results = {}
with open(f"{LOGS}/clamav.log", errors="replace") as f:
    for raw in f:
        line = raw.rstrip("\n")
        if not line.startswith(PREFIX):
            continue
        rel, rest = split_line(line)
        if rel is None:
            continue
        if rest == "OK":
            results.setdefault(rel, "OK")
        elif rest.endswith(" FOUND"):
            results[rel] = rest[:-len(" FOUND")]
        elif rest.endswith(" ERROR"):
            # Une détection déjà trouvée prime sur une erreur
            if results.get(rel, "OK") == "OK":
                results[rel] = "ERREUR:" + rest[:-len(" ERROR")].rstrip(". ")

write_json("clamav.json", results)

detections = sum(1 for v in results.values() if v != "OK" and not v.startswith("ERREUR:"))
errors = sum(1 for v in results.values() if v.startswith("ERREUR:"))
print(f"[+] ClamAV parsé : {detections} détection(s), {errors} fichier(s) en erreur")
