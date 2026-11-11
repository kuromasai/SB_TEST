#!/usr/bin/env python3
"""
scan_archives.py — Détecte les archives protégées par mot de passe / chiffrées.

Contexte : ClamAV ne peut pas inspecter le contenu d'une archive chiffrée. Il
est lancé avec l'alerte « contenu chiffré » activée, mais ce script reste une
seconde vérification indépendante : un fichier légitime sur une clé USB
hôpital n'a normalement aucune raison d'être chiffré de cette façon.

Formats vérifiés : ZIP/JAR (zipfile), 7z (py7zr), RAR (rarfile). tar et gzip
n'ont pas de chiffrement natif : ClamAV les décompresse lui-même.
Aucune extraction n'est faite, seuls les en-têtes sont lus.

Produit logs/archives.json au même format que docs.json/yara.json :
{ "chemin/relatif": ["FLAG1", ...] }
"""
import os
import zipfile

import magic

from common import MOUNT, is_regular_file, load_json, write_json

ZIP_MIMES = {"application/zip", "application/java-archive"}
SEVENZIP_MIMES = {"application/x-7z-compressed"}
RAR_MIMES = {"application/x-rar", "application/vnd.rar", "application/x-rar-compressed"}


def is_password_error(exc):
    # py7zr et rarfile lèvent une exception PasswordRequired quand l'en-tête est chiffré
    return "password" in type(exc).__name__.lower()


def check_zip(abs_path):
    try:
        with zipfile.ZipFile(abs_path) as zf:
            for info in zf.infolist():
                # bit 0 du flag = entrée chiffrée (mot de passe requis)
                if info.flag_bits & 0x1:
                    return ["ARCHIVE_PASSWORD_PROTECTED"]
    except zipfile.BadZipFile:
        return ["ARCHIVE_CORRUPTED_OR_INVALID"]
    except Exception:
        return ["ARCHIVE_READ_ERROR"]
    return []


def check_7z(abs_path):
    try:
        import py7zr
    except ImportError:
        return ["ARCHIVE_TYPE_NOT_ANALYZED"]
    try:
        with py7zr.SevenZipFile(abs_path, mode="r") as archive:
            if archive.needs_password():
                return ["ARCHIVE_PASSWORD_PROTECTED"]
    except Exception as e:
        return ["ARCHIVE_PASSWORD_PROTECTED"] if is_password_error(e) else ["ARCHIVE_READ_ERROR"]
    return []


def check_rar(abs_path):
    try:
        import rarfile
    except ImportError:
        return ["ARCHIVE_TYPE_NOT_ANALYZED"]
    try:
        with rarfile.RarFile(abs_path) as archive:
            if archive.needs_password():
                return ["ARCHIVE_PASSWORD_PROTECTED"]
    except Exception as e:
        return ["ARCHIVE_PASSWORD_PROTECTED"] if is_password_error(e) else ["ARCHIVE_READ_ERROR"]
    return []


def main():
    files = load_json("files.json")

    results = {}
    for rel_path in files:
        abs_path = os.path.join(MOUNT, rel_path)
        if not is_regular_file(abs_path):
            continue
        try:
            mime = magic.from_file(abs_path, mime=True)
        except Exception:
            continue

        if mime in ZIP_MIMES:
            flags = check_zip(abs_path)
        elif mime in SEVENZIP_MIMES:
            flags = check_7z(abs_path)
        elif mime in RAR_MIMES:
            flags = check_rar(abs_path)
        else:
            continue

        if flags:
            results[rel_path] = flags

    write_json("archives.json", results)

    protected = sum(1 for v in results.values() if "ARCHIVE_PASSWORD_PROTECTED" in v)
    print(f"[+] Vérification archives terminée : {len(results)} archive(s) signalée(s), dont {protected} protégée(s) par mot de passe")


if __name__ == "__main__":
    main()
