#!/usr/bin/env python3
"""
list_files.py — Inventaire et hash SHA-256 des fichiers de la clé.

Seuls les fichiers réguliers sont lus. Les liens symboliques, FIFO,
périphériques et sockets ne sont jamais ouverts (un FIFO bloquerait le scan,
un lien vers /dev/zero ne finirait jamais, un lien vers un fichier de l'hôte
le ferait copier en quarantaine) : ils sont inventoriés et signalés dans
special.json, au format des détecteurs { "chemin/relatif": ["FLAG"] }.
"""
import hashlib
import os
import stat

from common import MOUNT, rel_path, write_json

files = []
hashes = {}
special = {}


def flag(rel, label, hash_text):
    files.append(rel)
    hashes[rel] = hash_text
    special.setdefault(rel, []).append(label)


def on_walk_error(err):
    # Dossier illisible : os.walk le sauterait en silence
    rel = rel_path(err.filename) if err.filename else "?"
    flag(rel, "DOSSIER_ILLISIBLE", f"NON CALCULÉ ({err.strerror})")


def special_kind(mode):
    if stat.S_ISLNK(mode):
        return "LIEN_SYMBOLIQUE"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return "PERIPHERIQUE"
    if stat.S_ISSOCK(mode):
        return "SOCKET"
    return "INCONNU"


for root, dirnames, filenames in os.walk(MOUNT, onerror=on_walk_error):
    # os.walk ne suit pas les liens vers des dossiers : on les signale
    for dirname in dirnames:
        full_path = os.path.join(root, dirname)
        if os.path.islink(full_path):
            flag(rel_path(full_path), "FICHIER_SPECIAL:LIEN_SYMBOLIQUE",
                 "NON CALCULÉ (lien symbolique)")

    for filename in filenames:
        full_path = os.path.join(root, filename)
        relative = rel_path(full_path)
        try:
            mode = os.lstat(full_path).st_mode
        except OSError as e:
            flag(relative, "FICHIER_ILLISIBLE", f"ERREUR : {e}")
            continue

        if not stat.S_ISREG(mode):
            flag(relative, f"FICHIER_SPECIAL:{special_kind(mode)}",
                 "NON CALCULÉ (fichier spécial)")
            continue

        files.append(relative)
        sha256 = hashlib.sha256()
        try:
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            hashes[relative] = sha256.hexdigest()
        except OSError as e:
            hashes[relative] = f"ERREUR : {e}"
            special.setdefault(relative, []).append("FICHIER_ILLISIBLE")

write_json("files.json", files)
write_json("hashes.json", hashes)
write_json("special.json", special)

print(f"[+] {len(files)} fichier(s) inventorié(s) et hashé(s)")
if special:
    print(f"[!] {len(special)} élément(s) spécial(aux) ou illisible(s) signalé(s)")
