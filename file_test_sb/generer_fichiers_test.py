#!/usr/bin/env python3
"""
generer_fichiers_test.py — Génère un jeu de fichiers de test pour la Station Blanche.

Aucun vrai malware : les fichiers « infectés » contiennent la chaîne de test
EICAR (standard antivirus, inoffensive), les fichiers « suspects » sont des
leurres inoffensifs conçus pour déclencher chacun un détecteur précis.

Usage :
    python3 generer_fichiers_test.py <dossier_cible> [--sans-eicar] [--gros-fichier]

    --sans-eicar    n'écrit pas les fichiers EICAR (sinon Windows Defender
                    les supprime aussitôt sur un poste Windows)
    --gros-fichier  ajoute un fichier de 150 Mo (dépasse la limite ClamAV)

Pour tester une clé USB : la brancher sur une machine Linux, puis
    python3 generer_fichiers_test.py /media/<utilisateur>/<CLE>
Le résultat attendu de chaque fichier est décrit dans README.md.
"""
import io
import os
import random
import struct
import sys
import time
import zipfile
import zlib

# Chaîne EICAR découpée pour que ce script lui-même ne soit pas détecté
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
ZIP_PASSWORD = b"infected"


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------
def write(base, rel, data):
    path = os.path.join(base, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    print(f"  [+] {rel}")


def zip_bytes(entries):
    """Zip classique (non chiffré) en mémoire : [(nom, contenu)]."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


# --- Chiffrement ZIP traditionnel (ZipCrypto) : zipfile sait le lire, pas l'écrire
CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    CRC_TABLE.append(_c)


def _crc_byte(crc, b):
    return (crc >> 8) ^ CRC_TABLE[(crc ^ b) & 0xFF]


class ZipCrypto:
    def __init__(self, password):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for c in password:
            self._update(c)

    def _update(self, c):
        self.k0 = _crc_byte(self.k0, c)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc_byte(self.k2, (self.k1 >> 24) & 0xFF)

    def encrypt(self, data):
        out = bytearray()
        for p in data:
            t = (self.k2 | 2) & 0xFFFF
            out.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            self._update(p)
        return bytes(out)


def encrypted_zip_bytes(name, data, password=ZIP_PASSWORD):
    """Zip à une entrée, stockée sans compression et chiffrée en ZipCrypto."""
    name_b = name.encode()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    t = time.localtime()
    dos_time = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    dos_date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    header = bytes(random.getrandbits(8) for _ in range(11)) + bytes([crc >> 24])
    payload = ZipCrypto(password).encrypt(header + data)
    flags, method = 0x0001, 0
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, dos_time, dos_date,
                        crc, len(payload), len(data), len(name_b), 0) + name_b + payload
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, dos_time,
                          dos_date, crc, len(payload), len(data), len(name_b), 0, 0, 0, 0, 0,
                          0) + name_b
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def pdf_bytes(catalog_extra=b"", extra_objects=()):
    """PDF minimal valide (xref correcte). `catalog_extra` est ajouté au catalogue."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
    ] + list(extra_objects)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def png_bytes():
    """Image PNG 1x1 blanche."""
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\xff\xff")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def docx_bytes():
    """Document Word minimal sans macro."""
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>')
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>')
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>Compte rendu de test - document propre.</w:t></w:r></w:p>'
        '</w:body></w:document>')
    # [Content_Types].xml en premier : c'est ce que libmagic regarde
    return zip_bytes([("[Content_Types].xml", content_types),
                      ("_rels/.rels", rels),
                      ("word/document.xml", document)])


def rtf_equation_bytes():
    """RTF avec un objet OLE embarqué de classe Equation.3 (le composant visé
    par CVE-2017-11882). Les données de l'objet sont du remplissage inoffensif."""
    class_name = b"Equation.3\x00"
    native = b"\x00" * 32
    ole1 = (struct.pack("<II", 0x00000501, 0x00000002)
            + struct.pack("<I", len(class_name)) + class_name
            + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<I", len(native)) + native)
    return (b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}"
            b"{\\*\\objdata " + ole1.hex().encode() + b"}}}")


def mz_bytes():
    """En-tête d'exécutable DOS/Windows minimal (ne fait rien, non exécutable tel quel)."""
    header = bytearray(64)
    header[0:2] = b"MZ"
    struct.pack_into("<H", header, 2, 0x90)
    struct.pack_into("<I", header, 0x3C, 0)
    return bytes(header) + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 64


# ---------------------------------------------------------------------------
# Jeu de test
# ---------------------------------------------------------------------------
def generate(base, with_eicar, big_file):
    print("[+] Fichiers PROPRES")
    write(base, "propre/note.txt", "Note de service - fichier texte propre.\n")
    write(base, "propre/tableau.csv", "service;lits;occupes\ncardio;24;19\npneumo;18;12\n")
    write(base, "propre/image.png", png_bytes())
    write(base, "propre/document.pdf", pdf_bytes())
    write(base, "propre/rapport.docx", docx_bytes())
    write(base, "propre/lettre.rtf", "{\\rtf1\\ansi Lettre de test, sans objet embarque.}")
    write(base, "propre/archive_propre.zip", zip_bytes([("note.txt", "Contenu propre.\n")]))
    write(base, "propre/sous-dossier/profond/notes.txt", "Fichier propre dans un sous-dossier.\n")

    if with_eicar:
        print("[+] Fichiers INFECTÉS (EICAR)")
        write(base, "infecte/eicar.com", EICAR)
        write(base, "infecte/eicar_dans_zip.zip", zip_bytes([("eicar.com", EICAR)]))
        # Teste le scan récursif de YARA-X et de ClamAV
        write(base, "infecte/dossier/tres/profond/eicar.txt", EICAR)
    else:
        print("[~] Fichiers EICAR ignorés (--sans-eicar)")

    print("[+] Fichiers SUSPECTS (leurres inoffensifs)")
    write(base, "suspect/archive_mot_de_passe.zip",
          encrypted_zip_bytes("note.txt", b"Contenu inoffensif, archive chiffree.\n"))
    if with_eicar:
        # ClamAV ne voit pas EICAR à travers le chiffrement : seul le flag archive le signale
        write(base, "suspect/archive_mot_de_passe_eicar.zip", encrypted_zip_bytes("eicar.com", EICAR))
    write(base, "suspect/archive_corrompue.zip", b"PK\x03\x04" + b"\x00" * 10 + b"donnees tronquees")
    try:
        import py7zr
        path = os.path.join(base, "suspect/archive_mot_de_passe.7z")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with py7zr.SevenZipFile(path, "w", password=ZIP_PASSWORD.decode()) as archive:
            archive.writestr(b"Contenu inoffensif, archive 7z chiffree.\n", "note.txt")
        print("  [+] suspect/archive_mot_de_passe.7z")
    except ImportError:
        print("  [~] suspect/archive_mot_de_passe.7z ignoré (py7zr non installé)")

    write(base, "suspect/pdf_javascript.pdf", pdf_bytes(
        b"/OpenAction 4 0 R",
        [b"<< /Type /Action /S /JavaScript /JS (app.alert\\('Test station blanche'\\);) >>"]))
    # Même chose avec des noms obfusqués en hexadécimal (#61 = a, #4F = O)
    write(base, "suspect/pdf_obfusque.pdf", pdf_bytes(
        b"/#4FpenAction 4 0 R",
        [b"<< /Type /Action /S /J#61vaScript /JS (app.alert\\('Test'\\);) >>"]))
    write(base, "suspect/pdf_launch.pdf", pdf_bytes(
        b"/OpenAction 4 0 R",
        [b"<< /Type /Action /S /Launch /F (notepad.exe) >>"]))

    # Faux documents Word : texte VBA brut (olevba sait lire le VBA en texte)
    write(base, "suspect/macro_autoexec.doc",
          'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n'
          '    MsgBox "Test station blanche"\r\nEnd Sub\r\n')
    write(base, "suspect/macro_suspecte.doc",
          'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n'
          '    Shell "cmd /c echo test station blanche"\r\nEnd Sub\r\n')
    write(base, "suspect/rtf_equation.rtf", rtf_equation_bytes())
    write(base, "suspect/facture.pdf", mz_bytes())   # exécutable déguisé en PDF

    if big_file:
        path = os.path.join(base, "suspect/gros_fichier.bin")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            for _ in range(150):
                f.write(os.urandom(1024 * 1024))
        print("  [+] suspect/gros_fichier.bin (150 Mo)")

    # Fichiers spéciaux : Linux uniquement, et pas sur FAT/exFAT/NTFS
    if os.name == "posix":
        try:
            os.symlink("/etc/passwd", os.path.join(base, "suspect/lien_vers_etc_passwd"))
            print("  [+] suspect/lien_vers_etc_passwd (lien symbolique)")
        except OSError as e:
            print(f"  [~] lien symbolique impossible sur ce système de fichiers ({e.strerror})")
        try:
            os.mkfifo(os.path.join(base, "suspect/tube_fifo"))
            print("  [+] suspect/tube_fifo (FIFO)")
        except (OSError, AttributeError) as e:
            print(f"  [~] FIFO impossible sur ce système de fichiers ({getattr(e, 'strerror', e)})")
    else:
        print("  [~] lien symbolique et FIFO ignorés (Linux uniquement)")


def main():
    # Console Windows (cp1252) : évite un plantage sur les caractères accentués/✓
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__)
        sys.exit(1)
    base = args[0]
    os.makedirs(base, exist_ok=True)
    generate(base, with_eicar="--sans-eicar" not in sys.argv, big_file="--gros-fichier" in sys.argv)
    print(f"[✓] Jeu de test généré dans {base}")


if __name__ == "__main__":
    main()
