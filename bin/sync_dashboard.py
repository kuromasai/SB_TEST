#!/usr/bin/env python3
"""
sync_dashboard.py — Envoie au dashboard les scans en attente et un signal de vie.

Lancé par le service systemd station-blanche-sync (timer toutes les 10 min,
et déclenché par export_scan.py après chaque scan). Jamais lancé par le scan
lui-même : un dashboard injoignable ne bloque donc jamais une analyse.

1. Signal de vie (heartbeat) : versions des signatures, heure de la station,
   nombre d'envois en attente. Permet au dashboard de distinguer « aucune
   clé scannée » de « la station ne remonte plus rien ».
2. Scans en attente (spool/pending/), du plus ancien au plus récent :
   - accusé de réception -> fichier supprimé ;
   - refusé comme invalide (400, 413, 422) -> déplacé dans spool/rejected/
     pour ne pas bloquer les suivants ;
   - dashboard injoignable, erreur serveur ou jeton refusé -> arrêt,
     nouvel essai au prochain passage.

Réseau : uniquement l'URL configurée (une seule IP autorisée en sortie),
HTTPS avec le certificat du dashboard épinglé (`ca` dans la configuration).

Usage : sudo python3 /opt/station-blanche/bin/sync_dashboard.py [--test]
  --test : envoie seulement le signal de vie et affiche le résultat.
"""
import argparse
import fcntl
import json
import os
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime

from common import (
    PAYLOAD_FORMAT, SPOOL, SPOOL_PENDING, SPOOL_REJECTED,
    load_dashboard_config, signatures_info,
)

HEARTBEAT_TIMEOUT = 15
UPLOAD_TIMEOUT = 120
REJECTED_CODES = {400, 413, 422}


class Stop(Exception):
    """Arrête l'envoi : nouvel essai au prochain passage."""


def ssl_context(conf):
    ctx = ssl.create_default_context(cafile=conf["ca"]) if conf["ca"] else ssl.create_default_context()
    # Le certificat du dashboard est auto-signé et épinglé : on ne fait confiance
    # qu'à lui. Le mode strict de Python 3.13 refuse certains certificats
    # auto-signés générés par openssl ; l'épinglage garde la vérification utile.
    if conf["ca"] and hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def post(conf, ctx, endpoint, body, gzipped, timeout):
    """POST et renvoie (code HTTP, réponse JSON). Lève Stop si injoignable."""
    headers = {
        "Authorization": f"Bearer {conf['token']}",
        "Content-Type": "application/json",
        "X-SB-Clock": datetime.now().astimezone().isoformat(),
    }
    if gzipped:
        headers["Content-Encoding"] = "gzip"
    req = urllib.request.Request(f"{conf['url']}{endpoint}", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise Stop(f"dashboard injoignable ({reason})")
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        data = {}
    return code, data


def pending_files():
    try:
        names = sorted(n for n in os.listdir(SPOOL_PENDING) if n.endswith(".json.gz"))
    except FileNotFoundError:
        return []
    # Le nom commence par la date du scan (scan_id) : tri = ordre chronologique
    return [os.path.join(SPOOL_PENDING, n) for n in names]


def count(directory):
    try:
        return sum(1 for n in os.listdir(directory) if n.endswith(".json.gz"))
    except FileNotFoundError:
        return 0


def heartbeat(conf, ctx):
    body = json.dumps({
        "format": PAYLOAD_FORMAT,
        "station": conf["station"],
        "signatures": signatures_info(),
        "pending": len(pending_files()),
        "rejected": count(SPOOL_REJECTED),
    }).encode("utf-8")
    code, data = post(conf, ctx, "/api/v1/heartbeat", body, False, HEARTBEAT_TIMEOUT)
    if code in (401, 403):
        raise Stop(f"jeton refusé par le dashboard (HTTP {code}) — vérifier {conf['station']} et son jeton")
    if code != 200:
        raise Stop(f"signal de vie refusé (HTTP {code}) : {data.get('erreur', '')}")
    print(f"[+] Signal de vie reçu par le dashboard ({data.get('station', conf['station'])})")


def upload(conf, ctx, path):
    with open(path, "rb") as f:
        body = f.read()
    code, data = post(conf, ctx, "/api/v1/scans", body, True, UPLOAD_TIMEOUT)
    name = os.path.basename(path)
    if code in (200, 201):
        os.remove(path)
        print(f"[+] Scan envoyé : {name} ({data.get('resultat', 'reçu')})")
    elif code in REJECTED_CODES:
        os.makedirs(SPOOL_REJECTED, mode=0o700, exist_ok=True)
        shutil.move(path, os.path.join(SPOOL_REJECTED, name))
        print(f"[-] Scan refusé par le dashboard (HTTP {code}) : {name} déplacé dans "
              f"{SPOOL_REJECTED} — {data.get('erreur', '')}")
    elif code in (401, 403):
        raise Stop(f"jeton refusé par le dashboard (HTTP {code})")
    else:
        raise Stop(f"erreur du dashboard (HTTP {code}) sur {name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    conf = load_dashboard_config()
    if not conf:
        print("[~] Dashboard non configuré (/etc/station-blanche/dashboard.conf) : "
              f"{len(pending_files())} scan(s) gardé(s) en attente")
        return 1 if args.test else 0

    # Un seul envoi à la fois (timer et déclenchement après scan peuvent se croiser)
    os.makedirs(SPOOL, mode=0o700, exist_ok=True)
    lock = open(os.path.join(SPOOL, ".sync.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("[~] Envoi déjà en cours")
        return 0

    try:
        ctx = ssl_context(conf)
        heartbeat(conf, ctx)
        if args.test:
            return 0
        files = pending_files()
        for path in files:
            upload(conf, ctx, path)
        if files:
            print(f"[+] File d'envoi traitée ({count(SPOOL_PENDING)} restant(s))")
    except Stop as e:
        print(f"[!] Envoi interrompu : {e}. {count(SPOOL_PENDING)} scan(s) en attente, "
              f"nouvel essai au prochain passage.")
        return 1 if args.test else 0
    except (ssl.SSLError, OSError) as e:
        print(f"[!] Envoi interrompu : {e}. Nouvel essai au prochain passage.")
        return 1 if args.test else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
