# Jeu de test — Station Blanche

Aucun vrai malware. Les fichiers « infectés » contiennent la chaîne de test **EICAR**
(standard antivirus, inoffensive). Les « suspects » sont des leurres inoffensifs qui
déclenchent chacun un détecteur précis.

`generer_fichiers_test.py` génère le jeu complet. Le générer sous Linux : sous Windows,
Defender supprime les fichiers EICAR (option `--sans-eicar` pour s'en passer).

Ce dossier n'est pas déployé sur la station (exclu du rsync de l'installeur).

## Préparer une clé de test

Sur une machine **Linux** (pour avoir EICAR, le lien symbolique et le FIFO) :

```bash
python3 generer_fichiers_test.py /media/<utilisateur>/<CLE>               # jeu complet
python3 generer_fichiers_test.py /media/<utilisateur>/<CLE> --gros-fichier  # + fichier de 150 Mo
```

Le lien symbolique et le FIFO exigent une clé formatée en **ext4** : FAT, exFAT et NTFS
ne les supportent pas, et le script le signale. L'archive 7z exige `py7zr`, déjà installé
sur la station.

## Résultats attendus

**Verdict global attendu : INFECTÉ** (ou SUSPECT pour un jeu généré avec `--sans-eicar`).

| Fichier | Verdict | Détecté par |
|---|---|---|
| `propre/*` (8 fichiers, dont un sous-dossier) | PROPRE | — |
| `infecte/eicar.com` | INFECTÉ | ClamAV + YARA |
| `infecte/eicar_dans_zip.zip` | INFECTÉ | ClamAV (décompresse le zip) |
| `infecte/dossier/tres/profond/eicar.txt` | INFECTÉ | ClamAV + YARA — **vérifie le scan récursif de YARA-X** |
| `suspect/archive_mot_de_passe.zip` | SUSPECT | `ARCHIVE_PASSWORD_PROTECTED` (+ `Heuristics.Encrypted.Zip` côté ClamAV) |
| `suspect/archive_mot_de_passe_eicar.zip` | SUSPECT | `ARCHIVE_PASSWORD_PROTECTED` — EICAR caché par le chiffrement |
| `suspect/archive_mot_de_passe.7z` | SUSPECT | `ARCHIVE_PASSWORD_PROTECTED` |
| `suspect/archive_corrompue.zip` | SUSPECT | `ARCHIVE_CORRUPTED_OR_INVALID` |
| `suspect/pdf_javascript.pdf` | SUSPECT | `PDF_JAVASCRIPT`, `PDF_AUTO_ACTION` |
| `suspect/pdf_obfusque.pdf` | INFECTÉ | ClamAV (heuristique PDF sur les noms obfusqués) + `PDF_JAVASCRIPT`, `PDF_AUTO_ACTION` |
| `suspect/pdf_launch.pdf` | SUSPECT | `PDF_AUTO_ACTION`, `PDF_LAUNCH_ACTION` |
| `suspect/macro_autoexec.doc` | SUSPECT | `MACRO_AUTOEXEC` |
| `suspect/macro_suspecte.doc` | SUSPECT | `MACRO_AUTOEXEC`, `MACRO_SUSPICIOUS` |
| `suspect/rtf_equation.rtf` | SUSPECT | `RTF_OBJET_EMBARQUE`, `RTF_EQUATION_EDITOR` |
| `suspect/facture.pdf` | SUSPECT | `EXECUTABLE_DEGUISE:application/x-dosexec` |
| `suspect/gros_fichier.bin` (option) | SUSPECT | `Heuristics.Limits.Exceeded` (ClamAV) |
| `suspect/lien_vers_etc_passwd` (ext4) | SUSPECT | `FICHIER_SPECIAL:LIEN_SYMBOLIQUE` — jamais suivi ni copié |
| `suspect/tube_fifo` (ext4) | SUSPECT | `FICHIER_SPECIAL:FIFO` — le scan ne doit pas bloquer |

Points à contrôler en plus des verdicts :
- le rapport affiche le numéro de série de la clé, l'opérateur et la version des signatures ;
- la quarantaine est créée dans `quarantine/<date>_<série>/` et ne contient ni le lien ni le FIFO ;
- la section « Fichiers non analysés » liste les archives chiffrées, l'archive corrompue
  et les fichiers spéciaux.

## Limites

- Les deux `.doc` à macro sont des **faux documents** : du code VBA en texte brut, qu'olevba
  sait lire. Ils testent la chaîne olevba/mraptor, pas l'extraction depuis un vrai fichier
  Office. Pour ce cas, utiliser un `.docm` créé dans Word avec une macro `AutoOpen`.
- ClamAV peut ajouter ses propres détections heuristiques sur certains leurres (PDF, RTF).
  Le verdict reste le même, ou passe à INFECTÉ si ClamAV nomme une signature.
