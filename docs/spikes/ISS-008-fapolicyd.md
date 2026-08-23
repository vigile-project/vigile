# SPIKE ISS-008 — Capacités réelles de fapolicyd

> **Statut** : Terminé (GO avec périmètre explicite) — 2026-08-21
> **Issue** : ISS-008 ; décisions éclairées : RISK-04, ADR-0009, POLICY_MODEL §5
> **Méthode** : sources primaires uniquement (dépôt GitHub linux-application-whitelisting/fapolicyd : man pages brutes, code source ; packages/src.fedoraproject.org ; bodhi ; doc publique RHEL 9). Rien n'est supposé.

## 1. Versions (vérifiées)

| Cible | Version | Source |
|---|---|---|
| Amont (dernière release) | **v2.0.1** (2026-08-19) ; v2.0 (2026-07-23) ; v1.6 (2026-06-11) | tags GitHub |
| **Fedora 44** | **fapolicyd-2.0-1.fc44** (+ 1 patch backporté) | spec f44 src.fedoraproject.org |
| Fedora 43 | 2.0-1.fc43 | packages.fedoraproject.org |
| Fedora 45 / Rawhide | 2.0.1-1.fc45 / .fc46 | packages.fedoraproject.org + bodhi |

Projet **très actif** (release il y a 2 jours au moment du spike ; 1 729
commits ; mainteneur principal S. Grubb, Red Hat ; licence GPL-3.0 ;
suivi via GitHub Issues).

## 2. Langage de règles (fapolicyd.rules(5) v2.0) — faits vérifiés

- Format `decision perm subject : object`, **première correspondance gagne**.
- **Decisions** : allow, deny, allow_audit, deny_audit, allow_syslog,
  deny_syslog, allow_log, deny_log.
- **Perm** : `open`, `execute`, `any`. **Il n'existe PAS de perm `exec`**
  (vérifié dans la doc ET le parser) — la confusion vient du champ sujet
  `exe=` (exécutable du processus sujet).
- **Sujets** : all, auid, uid, gid, sessionid, pid, ppid, trust, comm, exe,
  dir, ftype, pattern (`normal`/`ld_so`/`ld_preload`/`static`).
- **Objets** : all, path, dir, device, ftype, trust, **FILE_HASH** (l'ancien
  SHA256HASH est déprécié).
- Globbing : préfixe `glob:` sur exe/path uniquement, fnmatch(3), **pas de
  `**`** ; guillemets pour les espaces (nouveauté 2.0) ; ensembles `%nom=`.
- **Sources de confiance** (fapolicyd.conf) : `rpmdb`, `file`
  (fapolicyd.trust + trust.d/, format v3 `chemin taille sha256`), `debdb`
  (Debian, pour la phase 5). Intégrité : `none` (défaut) / `size` / `ima` /
  `sha256` (+`rpm_sha256_only`).

## 3. Scripts et interpréteurs — la question centrale

- **Autoriser un script précis par hash : CONFIRMÉ** (objet `FILE_HASH`, ou
  entrée trust gérée par `fapolicyd-cli --file add`).
- **Refuser un shell « interactif » tout en gardant les scripts : CONFIRMÉ
  NON COUVERT** — position officielle (README/NOTES) : « il n'y a pas grande
  différence entre lancer un script et taper les commandes à la main ; on
  vérifie ce que le shell appelle ». Aucun attribut sujet (tty/pty) ne
  distingue l'interactif. Attribut partiel : `comm` (le kernel renomme le
  process au nom du script interprété) → règles « bash exécutant le script
  X », mais pas de blocage du bash interactif lui-même.
- **Alerte** : la politique livrée `rules.d/72-shell.rules` = `allow perm=any
  all : ftype=text/x-shellscript` **sans trust** — Vigile doit durcir
  explicitement (trust/FILE_HASH).
- Fenêtre TOCTOU documentée : interpréteurs lisant leur source
  incrémentalement → verrouiller les permissions des fichiers trustés.

## 4. Cas limites (tableau des capacités)

| Cas | Statut | Preuve |
|---|---|---|
| memfd / fexecve | **NON VÉRIFIÉ** (aucune mention doc/code ; à tester empiriquement sur F44) | — |
| Binaire **sujet** supprimé en cours d'exécution | **CONFIRMÉ couvert** | process.c strip « (deleted) » après /proc/PID/exe |
| Exécuter un fichier **objet** déjà supprimé | **NON VÉRIFIÉ** (lecture de code : le suffixe « (deleted) » serait conservé → non-trust → refus) | file.c |
| LD_PRELOAD / LD_AUDIT | **CONFIRMÉ couvert** | `pattern=ld_preload` (refuse même les libs trustées ; règle non activée par défaut) |
| Namespaces / conteneurs | **CONFIRMÉ non couvert** (workaround officiel runc ; `allow_filesystem_mark=1` possible mais « aucune source de trust conteneur ») | doc RHEL 9 |
| AppImage / Flatpak | **NON VÉRIFIÉ** (zéro occurrence dans le dépôt) | — |
| NFS **client** | **CONFIRMÉ non couvert** | fanotify n'émet pas l'événement ; `watch_fs` par défaut = ext4, xfs, tmpfs |
| NFS **serveur** | couvert par règle optionnelle (41-nfsd.rules) | README-rules |
| `ignore_mounts` | **angle mort documenté** : les interpréteurs trustés lisent les montages ignorés **en contournant fapolicyd** | fapolicyd.conf(5) |
| ELF malformé | couvert (40-bad-elf.rules) | rules.d |

## 5. Intégration (rechargement, validation, journaux)

- **Pas d'API D-Bus** (grep nul sur tout le dépôt) : intégration = fichiers
  + FIFO `/run/fapolicyd/fapolicyd.fifo` + signaux.
- Rechargement **transactionnel** : `fagenrules --load` compile rules.d vers
  compiled.rules (validation par le parser **avant** remplacement atomique) ;
  à chaud : `fapolicyd-cli --reload-rules` (FIFO). `SIGHUP` = recharge de la
  trustdb ; `SIGUSR1` = dump état/métriques.
- **Validation offline** : `fapolicyd-cli --check-rules <fichier> --lint`
  (parser du daemon sans chargement, avertissements avec fichier:ligne) —
  exactement le « validateur natif » exigé par la transaction SEC-501.
- **Refus** : audit (`ausearch -m fanotify`, requiert auditd + au moins une
  règle audit) et/ou syslog formaté (`syslog_format`, événements ≤ 512 o) —
  deux flux parsables pour le bouclage Vigile. Format exact de
  l'enregistrement FANOTIFY : NON VÉRIFIÉ (côté kernel/auditd).

## 6. Conséquences pour Vigile

**Le compilateur PEUT générer** : règles 2.0 (decisions × perm
open/execute/any, sujets/objets documentés, ensembles %, trust par
fapolicyd.trust/trust.d) ; cible la sémantique **2.0** (`FILE_HASH`, pas la
syntaxe sha256hash= des docs RHEL 9 qui décrivent 1.x) ; pipeline
générer → `--check-rules --lint` → `fagenrules` → reload FIFO, avec
rechargement transactionnel déjà conforme à SEC-501.

**À déclarer NON APPLICABLE plutôt qu'à simuler** (matrice de capacités) :
bash interactif (contrôle complémentaire à prévoir, hors fapolicyd) ; NFS
client ; conteneurs/namespaces ; memfd et objet supprimé (jusqu'à test
empirique) ; AppImage/Flatpak (jusqu'à test). Recommandations de durcissement
produites par le compilateur : durcir l'équivalent de 72-shell.rules,
`integrity ≥ size` (sha256/ima conseillé), `dir=untrusted` déprécié à éviter.

## 7. Sources

dépôt GitHub fapolicyd (README, NOTES, fapolicyd.rules.5, fapolicyd.conf.5,
fapolicyd-cli.8, fapolicyd.8, fapolicyd.trust.5, fagenrules.8, rules.d/) ;
tags GitHub ; packages.fedoraproject.org/pkgs/fapolicyd ;
src.fedoraproject.org/rpms/fapolicyd (spec f44) ; bodhi ;
docs.redhat.com (RHEL 9, chapitre fapolicyd).

## Conclusion

**GO** pour la phase 2 avec un périmètre **explicite** : allowlisting par
hash/trust confirmée, rechargement transactionnel et validation offline
confirmés, cas non couverts documentés et déclarés non applicables dans le
manifeste d'artefacts. RISK-04 ramené de « spike requis » à « écarts connus
et déclarés ».
