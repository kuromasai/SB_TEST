#!/bin/bash
# update_signatures.sh — Met à jour les signatures ClamAV et les règles YARA
# sans réinstaller la station. À lancer en root :
#   sudo bash /opt/station-blanche/update_signatures.sh
# Les règles YARA sont recompilées automatiquement au scan suivant (l'interface
# détecte que les fichiers de règles ont changé).
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Ce script doit être exécuté en root"
  exit 1
fi

BASE="/opt/station-blanche"

echo "[+] Mise à jour des signatures ClamAV"
systemctl stop clamav-freshclam || true
freshclam
systemctl start clamav-freshclam || true
# clamd recharge sa base de lui-même (SelfCheck) ; on force pour ne pas attendre
systemctl restart clamav-daemon 2>/dev/null || true
echo "[+] $(clamscan --version)"

for repo in signature-base elastic-artifacts; do
  dir="$BASE/yara_rules/$repo"
  if [ -d "$dir/.git" ]; then
    echo "[+] Mise à jour des règles YARA : $repo"
    # Échoue si le dépôt a été figé sur un commit précis (HEAD détachée) :
    # dans ce cas, changer la référence et relancer l'installeur.
    if git -C "$dir" pull --ff-only; then
      echo "[+] $repo : $(git -C "$dir" log -1 --format='%h (%cs)')"
    else
      echo "[!] $repo : mise à jour impossible (version figée ou dépôt modifié)"
    fi
  else
    echo "[!] $repo absent de $BASE/yara_rules — relancer l'installeur"
  fi
done

# Signal de vie immédiat : le dashboard voit tout de suite les nouvelles versions
systemctl start --no-block station-blanche-sync.service 2>/dev/null || true

echo "[✓] Mise à jour terminée — les règles YARA seront recompilées au prochain scan"
