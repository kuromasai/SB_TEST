#!/bin/bash
set -euo pipefail

#################################
# Vérification root
#################################
if [ "$EUID" -ne 0 ]; then
  echo "[-] Ce script doit être exécuté en root"
  exit 1
fi

#################################
# Utilisateur autorisé à lancer Station Blanche
#################################
SB_USER="${1:-}"
if [ -z "$SB_USER" ]; then
  echo "Usage: $0 <nom_utilisateur>"
  exit 1
fi
if ! id "$SB_USER" >/dev/null 2>&1; then
  echo "[-] L'utilisateur '$SB_USER' n'existe pas sur ce système"
  exit 1
fi

BASE="/opt/station-blanche"
PYTHON_BIN="$(command -v python3)"
MAIN_SCRIPT="$BASE/bin/station_blanche.py"
WRAPPER="/usr/local/bin/station-blanche"
SUDOERS_FILE="/etc/sudoers.d/station-blanche"

if [ ! -d "$BASE" ]; then
  echo "[-] $BASE introuvable — lancez d'abord install_station_blanche.sh"
  exit 1
fi
if [ ! -f "$MAIN_SCRIPT" ]; then
  echo "[-] $MAIN_SCRIPT introuvable"
  exit 1
fi

#################################
# Verrouillage du dossier Station Blanche
#################################
# root a un accès complet ; tout autre utilisateur (y compris SB_USER)
# n'a ni lecture, ni écriture, ni traversée du dossier.
echo "[+] Verrouillage de $BASE (root uniquement)"
chown -R root:root "$BASE"
chmod -R 700 "$BASE"

#################################
# Wrapper de lancement
#################################
echo "[+] Création du wrapper $WRAPPER"
cat > "$WRAPPER" << EOF
#!/bin/bash
exec sudo $PYTHON_BIN $MAIN_SCRIPT
EOF
chmod 755 "$WRAPPER"
chown root:root "$WRAPPER"

#################################
# Règle sudoers : uniquement ce binaire, uniquement pour SB_USER
#################################
echo "[+] Configuration sudoers pour '$SB_USER'"
echo "$SB_USER ALL=(root) NOPASSWD: $PYTHON_BIN $MAIN_SCRIPT" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
chown root:root "$SUDOERS_FILE"

# Validation syntaxique avant de considérer que c'est bon — si la syntaxe
# est invalide, visudo -c échoue et le script s'arrête (set -e).
visudo -c -f "$SUDOERS_FILE"

echo "[✓] Hardening terminé"
echo "[✓] '$SB_USER' peut lancer Station Blanche avec : station-blanche"
echo "[✓] '$SB_USER' n'a aucun accès en lecture/écriture direct sur $BASE"
