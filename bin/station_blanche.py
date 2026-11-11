#!/usr/bin/env python3
"""
Station Blanche - Application PyQt5
Interface graphique pour le scan USB sécurisé
"""

import sys
import os
import re
import json
import glob
import signal
import shutil
import hashlib
import tempfile
import threading
import subprocess
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QProgressBar, QComboBox,
    QTabWidget, QFrame, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt5.QtGui import QTextCursor, QPixmap
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings

from common import (
    BIN, LOGS, REPORTS, MOUNT, YARA_RULES, LOGO_PATH, CLAMAV_MAX_AGE_DAYS,
    CHU_BLUE_DARK, CHU_BLUE_LIGHT, CHU_GRAY, CHU_BG, CHU_SURFACE, CHU_BORDER, CHU_TEXT,
    STATUS_GREEN, STATUS_ORANGE, STATUS_RED,
    load_json, write_json, clamav_db_info, age_days,
)

STEPS = [
    ("Inventaire",         "list_files.py"),
    ("ClamAV",             None),
    ("Vérif. archives",    "scan_archives.py"),
    ("YARA-X",             None),
    ("Analyse documents",  "scan_docs.py"),
    ("Parsing ClamAV",     "parse_clamav.py"),
    ("Parsing YARA",       "parse_yara.py"),
    ("Corrélation",        "correlate.py"),
    ("Quarantaine",        "quarantine.py"),
    ("Rapport",            "generate_report.py"),
]
# Index de chaque étape, dérivé de STEPS : réordonner STEPS suffit
STEP_IDX = {label: i for i, (label, _) in enumerate(STEPS)}

# Délais maximum (secondes) : au-delà, le processus est tué et le scan échoue
PYTHON_TIMEOUT = 30 * 60
CLAMAV_TIMEOUT = 4 * 3600
YARA_COMPILE_TIMEOUT = 30 * 60
YARA_TIMEOUT = 4 * 3600
SYSTEM_CMD_TIMEOUT = 60

CLAMD_CONF = "/etc/clamav/clamd.conf"
# Options clamd indispensables pour qu'un fichier non analysé soit signalé
CLAMD_REQUIRED_OPTS = ("AlertExceedsMax", "AlertEncrypted")

YARA_COMPILED = f"{YARA_RULES}/compiled_rules.yarc"
YARA_COMPILED_SIG = f"{YARA_COMPILED}.sig"

LSBLK_COLUMNS = "NAME,TYPE,SIZE,MOUNTPOINT,TRAN,FSTYPE,LABEL,SERIAL,VENDOR,MODEL"

STYLE = f"""
QMainWindow, QWidget {{
    background-color: {CHU_BG};
    color: {CHU_TEXT};
    font-family: 'IBM Plex Sans', 'Segoe UI', 'Arial', sans-serif;
}}

QLabel#title {{
    font-size: 22px;
    font-weight: 600;
    color: {CHU_BLUE_DARK};
    padding: 10px 0px 2px 0px;
    letter-spacing: 0.5px;
}}

QLabel#subtitle {{
    font-size: 11px;
    color: {CHU_GRAY};
    padding-bottom: 10px;
}}

QLabel#section {{
    font-size: 11px;
    font-weight: 600;
    color: {CHU_GRAY};
    text-transform: uppercase;
    letter-spacing: 1.5px;
    padding-top: 8px;
}}

QLabel#device_label {{
    font-size: 13px;
    color: {CHU_TEXT};
}}

QLabel#status_clean {{
    font-size: 15px;
    font-weight: 600;
    color: {STATUS_GREEN};
    padding: 6px;
}}
QLabel#status_infected {{
    font-size: 15px;
    font-weight: 600;
    color: {STATUS_RED};
    padding: 6px;
}}
QLabel#status_suspicious {{
    font-size: 15px;
    font-weight: 600;
    color: {STATUS_ORANGE};
    padding: 6px;
}}
QLabel#status_idle {{
    font-size: 13px;
    color: {CHU_GRAY};
    padding: 6px;
}}

QComboBox {{
    background-color: {CHU_SURFACE};
    color: {CHU_TEXT};
    border: 1px solid {CHU_BORDER};
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 13px;
    min-width: 200px;
}}
QComboBox::drop-down {{
    border: none;
}}
QComboBox QAbstractItemView {{
    background-color: {CHU_SURFACE};
    color: {CHU_TEXT};
    border: 1px solid {CHU_BORDER};
    selection-background-color: {CHU_BLUE_LIGHT};
    selection-color: #ffffff;
}}

QPushButton#btn_scan {{
    background-color: {CHU_BLUE_DARK};
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 22px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton#btn_scan:hover {{
    background-color: {CHU_BLUE_LIGHT};
}}
QPushButton#btn_scan:disabled {{
    background-color: #C7CDD3;
    color: #F2F5F8;
}}

QPushButton#btn_cancel {{
    background-color: {CHU_SURFACE};
    color: {STATUS_RED};
    border: 1px solid {STATUS_RED};
    border-radius: 6px;
    padding: 8px 14px;
    font-size: 12px;
}}
QPushButton#btn_cancel:disabled {{
    color: #C7CDD3;
    border-color: {CHU_BORDER};
}}

QPushButton#btn_refresh {{
    background-color: {CHU_SURFACE};
    color: {CHU_GRAY};
    border: 1px solid {CHU_BORDER};
    border-radius: 6px;
    padding: 8px 14px;
    font-size: 12px;
}}
QPushButton#btn_refresh:hover {{
    background-color: {CHU_BG};
    color: {CHU_TEXT};
    border-color: {CHU_BLUE_LIGHT};
}}

QProgressBar {{
    background-color: {CHU_BORDER};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {CHU_BLUE_LIGHT};
    border-radius: 4px;
}}

QLabel#progress_status {{
    font-size: 11px;
    font-weight: 600;
    color: {CHU_GRAY};
}}

QTextEdit {{
    background-color: {CHU_SURFACE};
    color: {CHU_TEXT};
    border: 1px solid {CHU_BORDER};
    border-radius: 6px;
    font-family: 'IBM Plex Mono', 'Consolas', 'Monospace';
    font-size: 11px;
    padding: 8px;
}}

QTabWidget::pane {{
    border: 1px solid {CHU_BORDER};
    border-radius: 6px;
    background-color: {CHU_SURFACE};
}}
QTabBar::tab {{
    background-color: {CHU_BG};
    color: {CHU_GRAY};
    border: 1px solid {CHU_BORDER};
    border-bottom: none;
    padding: 8px 18px;
    font-size: 12px;
    border-radius: 4px 4px 0 0;
}}
QTabBar::tab:selected {{
    background-color: {CHU_SURFACE};
    color: {CHU_BLUE_DARK};
    font-weight: 600;
    border-color: {CHU_BORDER};
}}

QFrame#separator {{
    color: {CHU_BORDER};
    background-color: {CHU_BORDER};
    max-height: 1px;
}}

QLabel#step_active {{
    color: {CHU_BLUE_DARK};
    font-size: 12px;
    font-weight: 600;
}}
QLabel#step_done {{
    color: {STATUS_GREEN};
    font-size: 12px;
}}
QLabel#step_idle {{
    color: #B7BEC6;
    font-size: 12px;
}}
"""


class StepError(Exception):
    """Erreur bloquante d'une étape : message affiché à l'opérateur."""


class ScanCancelled(Exception):
    """Scan interrompu par l'opérateur."""


def list_block_devices():
    """Périphériques analysables, via `lsblk -J`.
    Renvoie une liste de dicts : partitions, et disques sans table de
    partitions portant directement un système de fichiers (clé « superfloppy »)."""
    out = subprocess.check_output(
        ["lsblk", "-J", "-p", "-o", LSBLK_COLUMNS], text=True, timeout=SYSTEM_CMD_TIMEOUT
    )
    devices = []

    def clean(value):
        return (value or "").strip()

    for disk in json.loads(out).get("blockdevices", []):
        if disk.get("type") != "disk":
            continue
        disk_info = {
            "usb": clean(disk.get("tran")) == "usb",
            "serial": clean(disk.get("serial")),
            "vendor": clean(disk.get("vendor")),
            "model": clean(disk.get("model")),
            "disk": clean(disk.get("name")),
        }
        parts = [c for c in disk.get("children") or [] if c.get("type") == "part"]
        if parts:
            members = parts
        elif clean(disk.get("fstype")):
            members = [disk]
        else:
            members = []
        member_names = [clean(m.get("name")) for m in members]
        for m in members:
            devices.append(dict(disk_info,
                                name=clean(m.get("name")),
                                size=clean(m.get("size")),
                                fstype=clean(m.get("fstype")),
                                label=clean(m.get("label")),
                                mountpoint=clean(m.get("mountpoint")),
                                disk_partitions=member_names))
    return devices


class ScanWorker(QThread):
    log_signal = pyqtSignal(str, str)   # message, level (info/warn/error/ok)
    step_signal = pyqtSignal(int)        # index de l'étape courante
    done_signal = pyqtSignal(str)        # chemin du rapport HTML
    error_signal = pyqtSignal(str)

    def __init__(self, device_info):
        super().__init__()
        self.device_info = device_info
        self.device = device_info["name"]
        self.scan_info = {}
        self._proc = None
        self._cancelled = False
        self._lock = threading.Lock()

    def emit_log(self, msg, level="info"):
        self.log_signal.emit(msg, level)

    # ------------------------------------------------------------------
    # Exécution des processus (timeout + annulation)
    # ------------------------------------------------------------------
    @staticmethod
    def _kill(proc):
        # Le processus est lancé dans sa propre session : on tue tout le groupe
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def cancel(self):
        self._cancelled = True
        with self._lock:
            proc = self._proc
        if proc and proc.poll() is None:
            self._kill(proc)

    def _check_cancel(self):
        if self._cancelled:
            raise ScanCancelled()

    def run_cmd(self, cmd, timeout, stdout_path=None, max_err_lines=50):
        """Lance `cmd`, affiche sa sortie dans le log et renvoie le code retour.
        Si `stdout_path` est donné, stdout y est aussi écrit et stderr est
        gardé à part (affiché à la fin, tronqué à `max_err_lines` lignes)."""
        self._check_cancel()
        err_file = tempfile.TemporaryFile() if stdout_path else None
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE,
            stderr=err_file if err_file else subprocess.STDOUT,
            text=True, errors="replace", start_new_session=True
        )
        with self._lock:
            self._proc = proc
        if self._cancelled:
            self._kill(proc)

        timed_out = threading.Event()

        def on_timeout():
            timed_out.set()
            self._kill(proc)

        timer = threading.Timer(timeout, on_timeout)
        timer.daemon = True
        timer.start()
        out = open(stdout_path, "w") if stdout_path else None
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self.emit_log(line)
                    if out:
                        out.write(line + "\n")
            proc.wait()
        finally:
            timer.cancel()
            if out:
                out.close()
            with self._lock:
                self._proc = None

        if err_file:
            err_file.seek(0)
            err_lines = [l.rstrip() for l in err_file.read().decode("utf-8", "replace").splitlines() if l.strip()]
            err_file.close()
            for l in err_lines[:max_err_lines]:
                self.emit_log(l, "warn")
            if len(err_lines) > max_err_lines:
                self.emit_log(f"[~] … {len(err_lines) - max_err_lines} ligne(s) supplémentaire(s) masquée(s)", "warn")

        self._check_cancel()
        if timed_out.is_set():
            raise StepError(f"Délai dépassé ({timeout // 60} min) : {os.path.basename(cmd[0])} interrompu.")
        return proc.returncode

    def run_python(self, script):
        return self.run_cmd(["python3", f"{BIN}/{script}"], PYTHON_TIMEOUT)

    def run_python_step(self, label, script):
        self.step_signal.emit(STEP_IDX[label])
        self.emit_log(f"[+] {label}")
        if self.run_python(script) != 0:
            raise StepError(f"Erreur lors de : {label}")

    # ------------------------------------------------------------------
    # Déroulement du scan
    # ------------------------------------------------------------------
    def run(self):
        try:
            self._run_scan()
        except ScanCancelled:
            self.error_signal.emit("Scan annulé par l'opérateur.")
        except StepError as e:
            self.error_signal.emit(str(e))
        except Exception as e:
            self.error_signal.emit(f"Erreur inattendue : {e}")

    def _write_scan_info(self):
        write_json("scan_info.json", self.scan_info)

    def _run_scan(self):
        os.makedirs(LOGS, exist_ok=True)
        os.makedirs(MOUNT, exist_ok=True)
        os.makedirs(REPORTS, exist_ok=True)

        # Nettoyage logs précédents
        for pattern in ("*.json", "*.log", "*.exitcode", "*.ndjson"):
            for f in glob.glob(f"{LOGS}/{pattern}"):
                os.remove(f)

        # Informations de traçabilité reprises dans le rapport
        now = datetime.now()
        ident = self.device_info.get("serial") or os.path.basename(self.device)
        self.scan_info = {
            "scan_id": f"{now:%Y-%m-%d_%H-%M-%S}_{re.sub(r'[^A-Za-z0-9._-]', '_', ident)}",
            "started": now.isoformat(),
            "operator": os.environ.get("SUDO_USER") or "root",
            "device": {k: self.device_info.get(k, "") for k in
                       ("name", "size", "fstype", "label", "serial", "vendor", "model")},
            "disk_partitions": self.device_info.get("disk_partitions", []),
        }
        self._write_scan_info()

        # Fraîcheur des signatures ClamAV
        clam_version, clam_date = clamav_db_info()
        clam_age = age_days(clam_date)
        self.emit_log(f"[~] Base ClamAV : {clam_version}")
        if clam_age is not None and clam_age > CLAMAV_MAX_AGE_DAYS:
            self.emit_log(f"[!] Base ClamAV datant de {clam_age} jours — mettre à jour les signatures", "warn")

        # Démontage automount existant (un périphérique peut avoir plusieurs points de montage)
        result = subprocess.run(
            ["findmnt", "-n", "-o", "TARGET", "--source", self.device],
            capture_output=True, text=True, timeout=SYSTEM_CMD_TIMEOUT
        )
        for existing in result.stdout.splitlines():
            existing = existing.strip()
            if existing:
                self.emit_log(f"[~] Démontage automount : {existing}")
                subprocess.run(["umount", existing], timeout=SYSTEM_CMD_TIMEOUT)

        # Point de montage déjà occupé (scan précédent interrompu)
        if self._is_mounted():
            subprocess.run(["umount", MOUNT], stderr=subprocess.DEVNULL, timeout=SYSTEM_CMD_TIMEOUT)

        # Montage
        self.emit_log(f"[+] Montage de {self.device} en lecture seule")
        ret = subprocess.run(
            ["mount", "-o", "ro,nosuid,nodev,noexec", self.device, MOUNT],
            timeout=SYSTEM_CMD_TIMEOUT
        ).returncode
        if ret != 0:
            raise StepError("Échec du montage — vérifiez le périphérique.")

        try:
            self._run_pipeline()
        finally:
            # Démontage garanti
            if self._is_mounted():
                self.emit_log("[+] Démontage")
                ret = subprocess.run(["umount", MOUNT], timeout=SYSTEM_CMD_TIMEOUT).returncode
                if ret != 0:
                    self.emit_log("[!] Démontage refusé, démontage différé (umount -l)", "warn")
                    subprocess.run(["umount", "-l", MOUNT], timeout=SYSTEM_CMD_TIMEOUT)

    @staticmethod
    def _is_mounted():
        return subprocess.run(["mountpoint", "-q", MOUNT],
                              timeout=SYSTEM_CMD_TIMEOUT).returncode == 0

    def _clamd_usable(self):
        """clamd est utilisé s'il répond et si sa configuration signale les
        fichiers trop gros et chiffrés ; sinon on retombe sur clamscan."""
        if not shutil.which("clamdscan"):
            return False
        try:
            with open(CLAMD_CONF) as f:
                conf = f.read()
        except OSError:
            return False
        for opt in CLAMD_REQUIRED_OPTS:
            if not re.search(rf"^\s*{opt}\s+(yes|true)\s*$", conf, re.M | re.I):
                self.emit_log(f"[~] clamd ignoré : option {opt} absente de {CLAMD_CONF}", "warn")
                return False
        try:
            return subprocess.run(["clamdscan", "--ping=1"], capture_output=True,
                                  timeout=15).returncode == 0
        except Exception:
            return False

    def _run_pipeline(self):
        # Étape : Inventaire
        self.run_python_step("Inventaire", "list_files.py")

        # Étape : ClamAV
        self.step_signal.emit(STEP_IDX["ClamAV"])
        if self._clamd_usable():
            # clamd garde les signatures en mémoire : pas de rechargement à chaque scan.
            # --fdpass : clamd (utilisateur clamav) lit les fichiers via nos descripteurs.
            engine = "clamdscan (démon clamd)"
            cmd = ["clamdscan", "--fdpass", "--stdout", f"--log={LOGS}/clamav.log", MOUNT]
        else:
            engine = "clamscan"
            cmd = ["clamscan", "-r", "--stdout",
                   "--alert-exceeds-max=yes", "--alert-encrypted=yes",
                   f"--log={LOGS}/clamav.log", MOUNT]
        self.scan_info["clamav_engine"] = engine
        self._write_scan_info()
        self.emit_log(f"[+] Scan ClamAV en cours ({engine})...")
        clam_exit = self.run_cmd(cmd, CLAMAV_TIMEOUT)
        with open(f"{LOGS}/clamav.exitcode", "w") as f:
            f.write(str(clam_exit))
        if clam_exit == 2:
            # Code 2 = au moins une erreur. Si le scan est allé au bout (résumé
            # présent), ce sont des erreurs par fichier : parse_clamav.py les
            # signale fichier par fichier (verdict SUSPECT). Sinon, échec réel.
            try:
                with open(f"{LOGS}/clamav.log", errors="replace") as f:
                    completed = "SCAN SUMMARY" in f.read()
            except OSError:
                completed = False
            if not completed:
                raise StepError("ClamAV a rencontré une erreur (code 2).")
            self.emit_log("[!] ClamAV n'a pas pu lire certains fichiers — ils seront marqués suspects", "warn")

        # Étape : Vérification archives (mot de passe / chiffrement)
        self.run_python_step("Vérif. archives", "scan_archives.py")

        # Étape : YARA-X
        self.step_signal.emit(STEP_IDX["YARA-X"])
        compiled = self._ensure_compiled_yara_rules()
        self.emit_log("[+] Scan YARA-X en cours...")
        # --recursive : sans lui, `yr scan` n'analyse pas les sous-dossiers.
        # Placé avant une autre option pour qu'il ne prenne jamais de valeur.
        yara_exit = self.run_cmd(
            ["yr", "scan", "--recursive", "--output-format=ndjson",
             "--compiled-rules", compiled, MOUNT],
            YARA_TIMEOUT, stdout_path=f"{LOGS}/yara.ndjson"
        )
        with open(f"{LOGS}/yara.exitcode", "w") as f:
            f.write(str(yara_exit))
        if yara_exit != 0:
            # Contrairement à yara classique (exit 1 = matches trouvés), yara-x
            # réserve un code non nul aux erreurs réelles.
            raise StepError(f"YARA-X a rencontré une erreur (code {yara_exit}).")

        # Étapes Python restantes
        self.run_python_step("Analyse documents", "scan_docs.py")
        self.run_python_step("Parsing ClamAV", "parse_clamav.py")
        self.run_python_step("Parsing YARA", "parse_yara.py")
        self.run_python_step("Corrélation", "correlate.py")
        self.run_python_step("Quarantaine", "quarantine.py")
        self.run_python_step("Rapport", "generate_report.py")

        # Trouver le rapport le plus récent
        reports = sorted(glob.glob(f"{REPORTS}/report_*.html"))
        if not reports:
            raise StepError("Rapport introuvable après génération.")
        self.done_signal.emit(reports[-1])

    def _ensure_compiled_yara_rules(self):
        """Compile les règles une seule fois (`yr compile`) et réutilise le
        résultat tant que les fichiers de règles ne changent pas.

        Certaines règles de signature-base utilisent des variables externes
        (filename, extension, owner...) non fournies ici : elles font échouer
        la compilation et sont exclues via external-variable-rules.txt. Comme
        `yr` prend un dossier et pas une liste d'exclusion, les règles gardées
        sont liées dans un dossier filtré temporaire."""
        all_rule_files = sorted(glob.glob(f"{YARA_RULES}/**/*.yar", recursive=True))
        if not all_rule_files:
            raise StepError(f"Aucune règle YARA trouvée dans {YARA_RULES}/")

        excluded_list_path = f"{YARA_RULES}/signature-base/yara/external-variable-rules.txt"
        excluded_names = set()
        if os.path.exists(excluded_list_path):
            with open(excluded_list_path) as f:
                excluded_names = {line.strip() for line in f if line.strip()}
        kept_files = [p for p in all_rule_files if os.path.basename(p) not in excluded_names]

        # Empreinte : liste des règles gardées + taille/date + version de yr
        yr_version = subprocess.run(["yr", "--version"], capture_output=True, text=True,
                                    timeout=SYSTEM_CMD_TIMEOUT).stdout.strip()
        digest = hashlib.sha256(yr_version.encode())
        for p in kept_files:
            st = os.stat(p)
            digest.update(f"{p}|{st.st_size}|{st.st_mtime_ns}\n".encode())
        signature = digest.hexdigest()

        try:
            with open(YARA_COMPILED_SIG) as f:
                up_to_date = f.read().strip() == signature and os.path.exists(YARA_COMPILED)
        except OSError:
            up_to_date = False
        if up_to_date:
            self.emit_log(f"[+] {len(kept_files)} fichier(s) de règles YARA (déjà compilés, "
                          f"{len(all_rule_files) - len(kept_files)} exclu(s) car variables externes)")
            return YARA_COMPILED

        self.emit_log(f"[+] Compilation de {len(kept_files)} fichier(s) de règles YARA "
                      f"({len(all_rule_files) - len(kept_files)} exclu(s) car variables externes)...")
        # Dossier caché dans yara_rules/ : même système de fichiers (hardlinks
        # possibles) et ignoré par le glob ci-dessus en cas de reliquat.
        filtered_dir = tempfile.mkdtemp(prefix=".yara_filtered_", dir=YARA_RULES)
        tmp_out = f"{YARA_COMPILED}.tmp"
        try:
            for rule_path in kept_files:
                dest = os.path.join(filtered_dir, os.path.relpath(rule_path, YARA_RULES))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                # Hardlink plutôt que symlink : yr pourrait ne pas suivre les
                # liens symboliques et charger silencieusement 0 règle.
                try:
                    os.link(rule_path, dest)
                except OSError:
                    shutil.copy2(rule_path, dest)
            ret = self.run_cmd(["yr", "compile", "--output", tmp_out, filtered_dir],
                               YARA_COMPILE_TIMEOUT, stdout_path=os.devnull)
        finally:
            shutil.rmtree(filtered_dir, ignore_errors=True)
        if ret != 0 or not os.path.exists(tmp_out):
            raise StepError(f"Échec de la compilation des règles YARA (code {ret}) — voir le log.")
        os.replace(tmp_out, YARA_COMPILED)
        with open(YARA_COMPILED_SIG, "w") as f:
            f.write(signature)
        self.emit_log("[+] Règles YARA compilées")
        return YARA_COMPILED


class StationBlanche(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Station Blanche")
        self.setMinimumSize(900, 650)
        self.worker = None
        self.scan_running = False
        self._devices = {}
        self._last_usb = set()
        self._build_ui()
        self._refresh_devices()

        # Timer de détection USB
        self.usb_timer = QTimer()
        self.usb_timer.timeout.connect(self._auto_detect_usb)
        self.usb_timer.start(2000)

    def _build_ui(self):
        self.setStyleSheet(STYLE)
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(0)

        # Header
        header_row = QHBoxLayout()
        header_row.setSpacing(14)

        logo_pixmap = QPixmap(LOGO_PATH)
        if not logo_pixmap.isNull():
            logo_label = QLabel()
            logo_label.setPixmap(
                logo_pixmap.scaledToHeight(40, Qt.SmoothTransformation)
            )
            header_row.addWidget(logo_label)

        title_col = QVBoxLayout()
        title_col.setSpacing(0)

        title = QLabel("Station Blanche")
        title.setObjectName("title")
        title_col.addWidget(title)

        subtitle = QLabel("Analyse de périphériques USB")
        subtitle.setObjectName("subtitle")
        title_col.addWidget(subtitle)

        header_row.addLayout(title_col)
        header_row.addStretch()
        root.addLayout(header_row)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        root.addWidget(sep)
        root.addSpacing(14)

        # Sélection périphérique
        dev_label = QLabel("PÉRIPHÉRIQUE")
        dev_label.setObjectName("section")
        root.addWidget(dev_label)
        root.addSpacing(6)

        dev_row = QHBoxLayout()
        dev_row.setSpacing(8)

        self.combo = QComboBox()
        dev_row.addWidget(self.combo)

        btn_refresh = QPushButton("↻ Actualiser")
        btn_refresh.setObjectName("btn_refresh")
        btn_refresh.clicked.connect(self._refresh_devices)
        dev_row.addWidget(btn_refresh)

        self.btn_scan = QPushButton("Lancer le scan")
        self.btn_scan.setObjectName("btn_scan")
        self.btn_scan.clicked.connect(self._start_scan)
        dev_row.addWidget(self.btn_scan)

        self.btn_cancel = QPushButton("Annuler")
        self.btn_cancel.setObjectName("btn_cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_scan)
        dev_row.addWidget(self.btn_cancel)

        dev_row.addStretch()
        root.addLayout(dev_row)
        root.addSpacing(16)

        # Étapes de progression
        steps_label = QLabel("PROGRESSION")
        steps_label.setObjectName("section")
        root.addWidget(steps_label)
        root.addSpacing(8)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)

        self.progress = QProgressBar()
        self.progress.setMaximum(len(STEPS))
        self.progress.setValue(0)
        progress_row.addWidget(self.progress, 1)

        self.progress_status = QLabel("0 %")
        self.progress_status.setObjectName("progress_status")
        self.progress_status.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.progress_status.setFixedWidth(50)
        progress_row.addWidget(self.progress_status)

        root.addLayout(progress_row)
        root.addSpacing(10)

        # Status
        self.status_label = QLabel("En attente d'un périphérique")
        self.status_label.setObjectName("status_idle")
        self.status_label.setAlignment(Qt.AlignCenter)
        root.addWidget(self.status_label)
        root.addSpacing(12)

        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFrameShape(QFrame.HLine)
        root.addWidget(sep2)
        root.addSpacing(10)

        # Onglets logs / rapport
        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        # Onglet logs
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.tabs.addTab(self.log_view, "Logs")

        # Onglet rapport — le rapport n'a besoin d'aucun JavaScript : on le
        # désactive (défense en profondeur, l'appli tourne en root et --no-sandbox)
        self.web_view = QWebEngineView()
        settings = self.web_view.settings()
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, False)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        self.web_view.setHtml(f"<body style='background:{CHU_SURFACE};color:{CHU_GRAY};font-family:sans-serif;padding:40px;text-align:center'><p style='margin-top:80px'>Le rapport apparaîtra ici à la fin du scan.</p></body>")
        self.tabs.addTab(self.web_view, "Rapport")

    def _refresh_devices(self):
        if self.scan_running:
            return
        previous = self.combo.currentData()
        self.combo.clear()
        self._devices = {}
        try:
            for dev in list_block_devices():
                self._devices[dev["name"]] = dev
                label = f"{dev['name']}  [{dev['size'] or '?'}]"
                if dev["usb"]:
                    label += "  USB"
                if dev["label"]:
                    label += f"  « {dev['label']} »"
                if dev["mountpoint"]:
                    label += f"  monté sur {dev['mountpoint']}"
                self.combo.addItem(label, dev["name"])
        except Exception as e:
            self.combo.addItem(f"Erreur : {e}")
        if previous:
            idx = self.combo.findData(previous)
            if idx >= 0:
                self.combo.setCurrentIndex(idx)

    def _auto_detect_usb(self):
        if self.scan_running:
            return
        try:
            usb = {d["name"] for d in list_block_devices() if d["usb"]}
        except Exception:
            return
        if usb == self._last_usb:
            return
        new_devs = usb - self._last_usb
        self._last_usb = usb
        self._refresh_devices()
        if new_devs:
            for i in range(self.combo.count()):
                if self.combo.itemData(i) in new_devs:
                    self.combo.setCurrentIndex(i)
                    break
            self._log("[~] Nouveau périphérique USB détecté — prêt au scan.", "info")

    def _set_running(self, running):
        self.scan_running = running
        self.btn_scan.setEnabled(not running)
        self.btn_cancel.setEnabled(running)

    def _start_scan(self):
        device = self.combo.currentData()
        dev_info = self._devices.get(device) if device else None
        if not dev_info:
            QMessageBox.warning(self, "Station Blanche", "Aucun périphérique sélectionné.")
            return

        self.log_view.clear()
        partitions = dev_info.get("disk_partitions", [])
        if len(partitions) > 1:
            msg = (f"La clé contient {len(partitions)} partitions ({', '.join(partitions)}). "
                   f"Seule {device} va être analysée : lancez un scan pour chacune.")
            self._log(f"[!] {msg}", "warn")
            QMessageBox.warning(self, "Station Blanche — plusieurs partitions", msg)

        self._set_running(True)
        self.progress.setValue(0)
        self.progress_status.setText("0 %")
        self.status_label.setText("Scan en cours…")
        self.status_label.setObjectName("status_idle")
        self.status_label.setStyleSheet(f"font-size:13px; color:{CHU_BLUE_DARK}; padding:6px;")
        self.tabs.setCurrentIndex(0)

        self.worker = ScanWorker(dev_info)
        self.worker.log_signal.connect(self._log)
        self.worker.step_signal.connect(self._on_step)
        self.worker.done_signal.connect(self._on_done)
        self.worker.error_signal.connect(self._on_error)
        self.worker.start()

    def _cancel_scan(self):
        if self.worker and self.worker.isRunning():
            self._log("[~] Annulation demandée — arrêt de l'étape en cours…", "warn")
            self.btn_cancel.setEnabled(False)
            self.worker.cancel()

    def closeEvent(self, event):
        # Fermer pendant un scan détruirait le QThread en cours (plantage,
        # clé laissée montée) : on annule proprement et on attend la fin.
        if self.worker and self.worker.isRunning():
            answer = QMessageBox.question(
                self, "Station Blanche",
                "Un scan est en cours. L'annuler et quitter ?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            self.worker.cancel()
            self.worker.wait(120000)
        event.accept()

    def _log(self, msg, level="info"):
        colors = {
            "info":  CHU_GRAY,
            "ok":    STATUS_GREEN,
            "warn":  STATUS_ORANGE,
            "error": STATUS_RED,
        }
        color = colors.get(level, CHU_GRAY)
        if "[+]" in msg or "[✓]" in msg:
            color = STATUS_GREEN
        elif "[-]" in msg:
            color = STATUS_RED
        elif "[!]" in msg or "[~]" in msg:
            color = STATUS_ORANGE

        # Échapper les caractères HTML pour éviter une injection depuis les sorties d'outils
        safe_msg = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.log_view.append(f'<span style="color:{color}">{safe_msg}</span>')
        self.log_view.moveCursor(QTextCursor.End)

    def _update_progress_status(self):
        total = self.progress.maximum() or 1
        pct = int(round(self.progress.value() / total * 100))
        self.progress_status.setText(f"{pct} %")

    def _on_step(self, idx):
        self.progress.setValue(idx)
        self._update_progress_status()

    def _on_done(self, report_path):
        self._set_running(False)
        self.progress.setValue(len(STEPS))
        self._update_progress_status()

        self._log(f"[✓] Rapport : {report_path}", "ok")

        # Verdict lu dans correlation.json
        verdict = "INCONNU"
        verdict_style = f"font-size:15px; font-weight:bold; color:{CHU_GRAY}; padding:6px;"
        try:
            corr = load_json("correlation.json")
            infected = sum(1 for v in corr.values() if v["verdict"] == "INFECTED")
            suspicious = sum(1 for v in corr.values() if v["verdict"] == "SUSPICIOUS")
            if infected:
                verdict = f"⚠ INFECTÉ — {infected} fichier(s)"
                verdict_style = f"font-size:15px; font-weight:bold; color:{STATUS_RED}; padding:6px;"
            elif suspicious:
                verdict = f"⚠ SUSPECT — {suspicious} fichier(s)"
                verdict_style = f"font-size:15px; font-weight:bold; color:{STATUS_ORANGE}; padding:6px;"
            else:
                verdict = "✓ PROPRE"
                verdict_style = f"font-size:15px; font-weight:bold; color:{STATUS_GREEN}; padding:6px;"
        except Exception as e:
            self._log(f"[!] Impossible de lire le verdict (correlation.json) : {e}", "warn")

        self.status_label.setText(verdict)
        self.status_label.setStyleSheet(verdict_style)

        # Afficher le rapport dans l'onglet
        self.web_view.load(QUrl.fromLocalFile(report_path))
        self.tabs.setCurrentIndex(1)

    def _on_error(self, msg):
        self._set_running(False)
        self._log(f"[-] ERREUR : {msg}", "error")
        self.status_label.setText("Erreur lors du scan")
        self.status_label.setStyleSheet(f"font-size:15px; font-weight:bold; color:{STATUS_RED}; padding:6px;")
        if self.isVisible():
            QMessageBox.critical(self, "Erreur — Station Blanche", msg)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Cette application doit être lancée en root (sudo).")
        sys.exit(1)

    # Désactiver le session manager Qt (erreur XSMP quand lancé en root)
    os.environ["SESSION_MANAGER"] = ""

    sys.argv += ["--no-sandbox"]
    app = QApplication(sys.argv)
    app.setApplicationName("Station Blanche")
    window = StationBlanche()
    window.show()
    sys.exit(app.exec_())
