#!/usr/bin/env python3
"""
scan_docs.py — Analyse spécialisée des documents et des types trompeurs.

- Office (97-2003, OOXML, formats à macros .docm/.xlsm/.pptm…) : oletools
  (olevba + mraptor). Le type est reconnu par MIME **ou** par extension, car
  libmagic renvoie souvent application/CDFV2 ou application/zip pour de vrais
  documents Office.
- RTF : oletools.rtfobj (objets OLE embarqués, éditeur d'équations
  CVE-2017-11882). Un .doc qui est en réalité un RTF passe par cette branche.
- PDF : recherche de mots-clés à la PDFiD, en décodant les noms obfusqués
  (/J#61vaScript) et en lisant le fichier par blocs.
- Tout fichier : exécutable déguisé (MIME exécutable, extension qui ne l'est pas).

Produit logs/docs.json au format { "chemin/relatif": ["FLAG1", "FLAG2"] }.
"""
import os
import re

import magic

from common import MOUNT, is_regular_file, load_json, write_json

OFFICE_MIMES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.ms-office",
    "application/CDFV2",
    "application/x-ole-storage",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-word.template.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    "application/vnd.ms-excel.template.macroEnabled.12",
    "application/vnd.ms-excel.addin.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
    "application/vnd.ms-powerpoint.template.macroEnabled.12",
    "application/vnd.ms-powerpoint.addin.macroEnabled.12",
}
OFFICE_EXTS = {
    ".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm",
    ".xls", ".xlt", ".xla", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".xlam",
    ".ppt", ".pps", ".pot", ".pptx", ".pptm", ".ppsx", ".ppsm", ".potx", ".potm", ".ppam",
}
RTF_MIMES = {"text/rtf", "application/rtf"}
PDF_MIME = "application/pdf"

EXECUTABLE_MIMES = {
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
}
# Extensions pour lesquelles un contenu exécutable est attendu (pas de déguisement)
EXECUTABLE_EXTS = {
    "", ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi",
    ".msi", ".mui", ".so", ".bin", ".elf", ".run", ".appimage", ".out", ".o", ".ko",
}

# Mots-clés PDF (noms décodés) -> flag
PDF_KEYWORDS = {
    "/JS": "PDF_JAVASCRIPT",
    "/JavaScript": "PDF_JAVASCRIPT",
    "/AA": "PDF_AUTO_ACTION",
    "/OpenAction": "PDF_AUTO_ACTION",
    "/EmbeddedFile": "PDF_EMBEDDED_FILE",
    "/Launch": "PDF_LAUNCH_ACTION",
    "/RichMedia": "PDF_RICH_MEDIA",
}
# Un nom PDF : « / » suivi de caractères réguliers (tout sauf blancs et délimiteurs)
PDF_NAME_RE = re.compile(rb"/[^\s()<>\[\]{}/%]*")
PDF_HEX_ESCAPE_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
PDF_CHUNK = 1024 * 1024
PDF_MAX_NAME = 4096


def scan_office(abs_path):
    flags = []
    try:
        from oletools.olevba import VBA_Parser
        from oletools.mraptor import MacroRaptor

        vba_parser = VBA_Parser(abs_path)
        try:
            if vba_parser.detect_vba_macros():
                macros = [code for (_, _, _, code) in vba_parser.extract_macros()]
                raptor = MacroRaptor("\n".join(macros))
                raptor.scan()
                if raptor.autoexec:
                    flags.append("MACRO_AUTOEXEC")
                if raptor.suspicious:
                    flags.append("MACRO_SUSPICIOUS")
            if hasattr(vba_parser, "detect_dde") and vba_parser.detect_dde():
                flags.append("EXTERNAL_LINK_DDE")
        finally:
            vba_parser.close()
    except Exception as e:
        # fichier corrompu / format non supporté par oletools -> à traiter
        # comme suspect plutôt que de le laisser passer silencieusement
        flags.append(f"OFFICE_PARSE_ERROR:{type(e).__name__}")
    return flags


def scan_rtf(abs_path):
    flags = []
    try:
        from oletools.rtfobj import RtfObjParser

        with open(abs_path, "rb") as f:
            parser = RtfObjParser(f.read())
        parser.parse()
        for obj in parser.objects:
            if "RTF_OBJET_EMBARQUE" not in flags:
                flags.append("RTF_OBJET_EMBARQUE")
            class_name = (getattr(obj, "class_name", None) or b"").lower()
            if b"equation" in class_name and "RTF_EQUATION_EDITOR" not in flags:
                flags.append("RTF_EQUATION_EDITOR")
    except Exception as e:
        flags.append(f"RTF_PARSE_ERROR:{type(e).__name__}")
    return flags


def pdf_names(abs_path):
    """Ensemble des noms PDF (après décodage #xx) lus par blocs de 1 Mo.
    Un nom coupé en fin de bloc est reporté sur le bloc suivant."""
    names = set()
    tail = b""
    with open(abs_path, "rb") as f:
        while True:
            chunk = f.read(PDF_CHUNK)
            eof = not chunk
            buf = tail + chunk
            if eof:
                cut = len(buf)
            else:
                cut = buf.rfind(b"/")
                if cut == -1 or cut < len(buf) - PDF_MAX_NAME:
                    cut = len(buf)
            for m in PDF_NAME_RE.finditer(buf, 0, cut):
                names.add(PDF_HEX_ESCAPE_RE.sub(lambda h: bytes([int(h.group(1), 16)]), m.group()))
            tail = buf[cut:]
            if eof:
                return names


def scan_pdf(abs_path):
    try:
        names = pdf_names(abs_path)
    except Exception:
        return ["PDF_READ_ERROR"]
    flags = []
    for keyword, flag in PDF_KEYWORDS.items():
        if keyword.encode() in names and flag not in flags:
            flags.append(flag)
    return flags


def check_disguised_executable(rel_path, mime):
    ext = os.path.splitext(rel_path)[1].lower()
    if mime in EXECUTABLE_MIMES and ext not in EXECUTABLE_EXTS:
        return [f"EXECUTABLE_DEGUISE:{mime}"]
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
        ext = os.path.splitext(rel_path)[1].lower()

        flags = check_disguised_executable(rel_path, mime)
        if mime in RTF_MIMES or (ext == ".rtf" and mime.startswith("text/")):
            flags += scan_rtf(abs_path)
        elif mime == PDF_MIME or ext == ".pdf":
            flags += scan_pdf(abs_path)
        elif mime in OFFICE_MIMES or ext in OFFICE_EXTS:
            flags += scan_office(abs_path)

        if flags:
            results[rel_path] = flags

    write_json("docs.json", results)

    total_flags = sum(len(v) for v in results.values())
    print(f"[+] Analyse documents terminée : {len(results)} fichier(s) flagué(s), {total_flags} indicateur(s)")


if __name__ == "__main__":
    main()
