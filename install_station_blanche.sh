#!/bin/bash
set -e

echo "[+] Installation Station Blanche – Debian 13"

#################################
# Vérification root
#################################
if [ "$EUID" -ne 0 ]; then
  echo "[-] Ce script doit être exécuté en root"
  exit 1
fi

#################################
# Vérification OS
#################################
if ! grep -q 'VERSION_ID="13"' /etc/os-release; then
  echo "[-] Ce script est prévu pour Debian 13 uniquement"
  exit 1
fi

#################################
# Utilisateur autorisé à lancer Station Blanche
#################################
SB_USER="${1:-}"
if [ -z "$SB_USER" ]; then
  read -rp "[?] Nom de l'utilisateur qui doit pouvoir lancer Station Blanche : " SB_USER
fi
if ! id "$SB_USER" >/dev/null 2>&1; then
  echo "[-] L'utilisateur '$SB_USER' n'existe pas sur ce système"
  exit 1
fi

#################################
# Variables
#################################
BASE="/opt/station-blanche"
# Repo public -> clone HTTPS anonyme, aucun identifiant ni clé nécessaire.
REPO_URL="https://github.com/kuromasai/SB_TEST.git"
YARA_RULES_URL="https://github.com/Neo23x0/signature-base.git"
ELASTIC_RULES_URL="https://github.com/elastic/protections-artifacts.git"
CLAMD_CONF="/etc/clamav/clamd.conf"

# Versions figées (installation reproductible). Vide = dernière version, avec
# un avertissement. À renseigner avec un tag/commit validé, par ex. :
#   sudo SB_REF=v1.0 SIGBASE_REF=<commit> ./install_station_blanche.sh <utilisateur>
SB_REF="${SB_REF:-}"                  # tag ou commit du dépôt Station Blanche
SIGBASE_REF="${SIGBASE_REF:-}"        # commit de Neo23x0/signature-base
ELASTIC_REF="${ELASTIC_REF:-}"        # commit de elastic/protections-artifacts
YARA_X_VERSION="${YARA_X_VERSION:-}"  # version de yara-x-cli (crates.io)

# Clone un dépôt puis se place sur la référence demandée si elle est fournie
clone_at_ref() {
  local url="$1" dest="$2" ref="$3"
  git clone "$url" "$dest"
  if [ -n "$ref" ]; then
    git -C "$dest" checkout --quiet "$ref"
    echo "[+] $(basename "$dest") figé sur $ref"
  else
    echo "[!] $(basename "$dest") : aucune version figée, dernière version utilisée"
  fi
}

TMP_DIR=$(mktemp -d /tmp/station-blanche-install-XXXXXX)

# Nettoyage du dossier temporaire à la fin quoi qu'il arrive
cleanup() {
  echo "[+] Nettoyage du dossier temporaire"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

#################################
# Mise à jour système
#################################
echo "[+] Mise à jour système"
apt update && apt upgrade -y

#################################
# Installation dépendances système
#################################
echo "[+] Installation des dépendances"
apt install -y \
  clamav clamav-daemon \
  python3 python3-pip \
  python3-pyqt5 \
  python3-pyqt5.qtwebengine \
  libxcb-xinerama0 \
  libxcb-cursor0 \
  libmagic1 \
  git \
  rsync \
  curl \
  build-essential

# Police IBM Plex : purement esthétique (l'interface et le rapport retombent sur
# Arial/sans-serif). Absente de certains dépôts Debian : ne bloque pas l'installation.
if apt-cache show fonts-ibm-plex >/dev/null 2>&1; then
  apt install -y fonts-ibm-plex || echo "[!] Police IBM Plex non installée — police par défaut utilisée"
else
  echo "[!] Paquet fonts-ibm-plex indisponible — police par défaut utilisée"
fi

#################################
# Installation YARA-X (binaire `yr`)
#################################
# Pas de paquet apt pour yara-x sur Debian 13, et le rustc fourni par apt
# (1.85.0) est trop ancien pour yara-x-cli, y compris ses anciennes versions
# (dépendances transitives qui exigent 1.88+/1.91+). Plutôt que de courir
# après une version de yara-x-cli compatible avec un rustc figé, on installe
# un toolchain Rust à jour via rustup, isolé du rustc système.
echo "[+] Installation de rustup (toolchain Rust à jour, nécessaire pour yara-x-cli)"
export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source /opt/cargo/env

echo "[+] Compilation de YARA-X (yr) via cargo"
# --locked : utilise les versions de dépendances publiées avec le crate
if [ -n "$YARA_X_VERSION" ]; then
  cargo install yara-x-cli --locked --version "$YARA_X_VERSION" --root /usr/local
else
  echo "[!] yara-x-cli : aucune version figée, dernière version utilisée"
  cargo install yara-x-cli --locked --root /usr/local
fi
if ! command -v yr >/dev/null 2>&1; then
  echo "[-] yr introuvable dans le PATH après compilation — vérifier /usr/local/bin"
  exit 1
fi
echo "[+] $(yr --version)"

#################################
# Clone du repo Station Blanche
#################################
echo "[+] Clonage du repo Station Blanche"
clone_at_ref "$REPO_URL" "$TMP_DIR/Station-blanche" "$SB_REF"
SOURCE_DIR="$TMP_DIR/Station-blanche"

#################################
# Dépendances Python (pip)
#################################
if [ -f "$SOURCE_DIR/requirements.txt" ]; then
  echo "[+] Installation des dépendances Python"
  pip3 install --break-system-packages -r "$SOURCE_DIR/requirements.txt"
else
  echo "[!] Aucun requirements.txt trouvé – pip3 non utilisé"
fi

#################################
# Dépendances Python pour l'étape "Analyse documents" (scan_docs.py)
#################################
echo "[+] Installation des dépendances Python pour l'analyse Office/PDF/archives"
pip3 install --break-system-packages python-magic oletools py7zr rarfile

#################################
# Mise à jour signatures ClamAV
#################################
echo "[+] Mise à jour ClamAV"
systemctl stop clamav-freshclam || true
freshclam
systemctl start clamav-freshclam || true

#################################
# Configuration du démon clamd
#################################
# L'interface utilise clamdscan (signatures gardées en mémoire, pas de
# rechargement à chaque scan) uniquement si clamd signale les fichiers trop
# gros et le contenu chiffré ; sinon elle retombe sur clamscan.
echo "[+] Configuration de clamd"
set_clamd_option() {
  local key="$1" value="$2"
  if grep -qE "^[#[:space:]]*${key}[[:space:]]" "$CLAMD_CONF"; then
    sed -i -E "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$CLAMD_CONF"
  else
    echo "${key} ${value}" >> "$CLAMD_CONF"
  fi
}
if [ -f "$CLAMD_CONF" ]; then
  set_clamd_option AlertExceedsMax yes
  set_clamd_option AlertEncrypted yes
  systemctl enable clamav-daemon || true
  systemctl restart clamav-daemon || echo "[!] clamd n'a pas démarré — clamscan sera utilisé"
else
  echo "[!] $CLAMD_CONF introuvable — clamscan sera utilisé"
fi

#################################
# Déploiement Station Blanche
#################################
echo "[+] Déploiement vers $BASE"
if [ -d "$BASE" ]; then
  echo "[!] $BASE existe déjà – mise à jour du contenu"
else
  mkdir -p "$BASE"
fi

# Les dossiers runtime sont exclus : sans ça, --delete effacerait la
# quarantaine, les rapports et les logs à chaque réinstallation.
rsync -a --delete \
  --exclude='.git' \
  --exclude='/file_test_sb/' \
  --exclude='/logs/' \
  --exclude='/mount/' \
  --exclude='/quarantine/' \
  --exclude='/reports/' \
  --exclude='/yara_rules/compiled_rules.yarc*' \
  "$SOURCE_DIR/" \
  "$BASE/"

#################################
# Clone des règles YARA signature-base
#################################
echo "[+] Clonage des règles YARA (Neo23x0/signature-base)"
# Supprimer l'ancien dossier si présent (reinstall)
rm -rf "$BASE/yara_rules/signature-base"
clone_at_ref "$YARA_RULES_URL" "$BASE/yara_rules/signature-base" "$SIGBASE_REF"

RULES_COUNT=$(find "$BASE/yara_rules/signature-base/yara" -name "*.yar" | wc -l)
echo "[+] $RULES_COUNT fichiers Neo23x0 téléchargés"

#################################
# Clone des règles YARA Elastic
#################################
echo "[+] Clonage des règles YARA (elastic/protections-artifacts)"
rm -rf "$BASE/yara_rules/elastic-artifacts"
clone_at_ref "$ELASTIC_RULES_URL" "$BASE/yara_rules/elastic-artifacts" "$ELASTIC_REF"

ELASTIC_COUNT=$(find "$BASE/yara_rules/elastic-artifacts/yara/rules" -name "*.yar" | wc -l)
echo "[+] $ELASTIC_COUNT fichiers Elastic téléchargés"

TOTAL_COUNT=$(find "$BASE/yara_rules" -name "*.yar" | wc -l)
echo "[+] Total règles YARA : $TOTAL_COUNT"

#################################
# Création dossiers runtime
#################################
echo "[+] Création des dossiers runtime"
mkdir -p "$BASE/logs" "$BASE/mount" "$BASE/quarantine" "$BASE/reports"

#################################
# Hardening : droits, wrapper, sudoers
#################################
# Toute la logique de permissions (chown/chmod, wrapper /usr/local/bin,
# règle sudoers) vit dans harden_station_blanche.sh pour rester
# ré-exécutable indépendamment du reste du déploiement.
if [ -f "$BASE/harden_station_blanche.sh" ]; then
  echo "[+] Application du hardening pour l'utilisateur '$SB_USER'"
  chmod +x "$BASE/harden_station_blanche.sh"
  "$BASE/harden_station_blanche.sh" "$SB_USER"
else
  echo "[-] harden_station_blanche.sh introuvable dans $BASE — hardening non appliqué"
  exit 1
fi

#################################
echo ""
echo "[✓] Installation terminée"
echo "[✓] Station Blanche installée dans $BASE"
echo "[✓] Règles YARA Neo23x0 : $BASE/yara_rules/signature-base/yara/"
echo "[✓] Règles YARA Elastic  : $BASE/yara_rules/elastic-artifacts/yara/rules/"
echo "[✓] Script principal : $BASE/bin/station_blanche.py"
echo "[✓] Mise à jour des signatures : sudo bash $BASE/update_signatures.sh"
echo "[✓] Les règles YARA seront compilées au premier scan (plus long que les suivants)"
echo "[✓] Utilisateur '$SB_USER' peut lancer l'appli via la commande : station-blanche"
