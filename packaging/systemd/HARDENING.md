# Audit de durcissement systemd — ISS-041

> Ce document justifie chaque choix de durcissement des unités
> `vigile-agent.service` et `vigile-executor.service`. Il sert de
> référence pour la revue de sécurité et doit être mis à jour à chaque
> modification des unités.

## 1. Analyse des capabilities

### vigile-agent (utilisateur `vigile`, non privilégié)

| Capability | Nécessaire ? | Justification |
|---|---|---|
| (aucune) | — | L'agent se connecte au serveur en HTTPS sortant (ports éphémères ≥ 1024, pas de CAP_NET_BIND_SERVICE). Il écrit dans /var/lib/vigile (possédé par l'utilisateur vigile). Il lit /etc/os-release et parcourt les répertoires avec les permissions standard. |

**CapabilityBoundingSet=** (vide) — l'agent n'a **aucune** capability Linux.

### vigile-executor (root, privilégié minimal)

| Capability | Nécessaire | Justification |
|---|---|---|
| CAP_DAC_OVERRIDE | **Oui** | Écrit des fichiers dans /etc/fapolicyd/ dont le propriétaire peut être `fapolicyd` ou `root`. Sans cette capability, les opérations d'écriture échoueraient selon les permissions Unix standard. |
| CAP_FOWNER | **Oui** | Change le propriétaire des fichiers créés (le champ `owner` de l'ArtifactSpec). Permet également d'opérer sur des fichiers indépendamment de leur propriétaire. |
| CAP_KILL | **Non*** | Rechargement de fapolicyd via signal. *Alternative recommandée : utiliser `systemctl reload fapolicyd` depuis l'exécuteur — dans ce cas CAP_KILL n'est pas nécessaire. Retirée pour le MVP car le rechargement sera fait via systemctl (action `ValidateArtifacts` + `Commit`). |
| CAP_SYS_ADMIN | **Non** | Pas de montage, pas de namespaces. |
| CAP_NET_BIND_SERVICE | **Non** | Pas de réseau du tout. |
| CAP_SYS_CHROOT | **Non** | Pas de chroot. |
| CAP_SETPCAP | **Non** | Pas de transfert de capabilities. |

**CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER**

*Note : si le MVP nécessite un `kill()` direct pour SIGHUP fapolicyd,
ajouter CAP_KILL avec un ADR dédié.*

## 2. Justification des directives de durcissement

### Directives filesystem

| Directive | Agent | Exécuteur | Raison |
|---|---|---|---|
| ProtectSystem=strict | ✓ | ✓ | Tout le système de fichiers est en lecture seule sauf ReadWritePaths explicites. Réduit la surface en cas de compromission. |
| ReadWritePaths | /var/lib/vigile | /var/lib/vigile/executor, /etc/fapolicyd, /run/vigile | **Liste minimale** : seulement ce dont chaque composant a besoin pour fonctionner. |
| ProtectHome=yes | ✓ | ✓ | /home et /root inaccessibles. Aucun composant n'a besoin d'y accéder. |
| PrivateTmp=yes | ✓ | ✓ | /tmp privé (namespaces). Empêche les attaques par fichiers temporaires partagés. |
| PrivateDevices=yes | ✓ | ✓ | /dev minimal. Aucun accès direct aux périphériques. |
| StateDirectory=vigile | ✓ | — | Crée /var/lib/vigile avec les bonnes permissions (0750). |
| RuntimeDirectory=vigile | — | ✓ | Crée /run/vigile pour le socket IPC. |

### Directives kernel

| Directive | Agent | Exécuteur | Raison |
|---|---|---|---|
| ProtectKernelTunables | ✓ | ✓ | /proc/sys en lecture seule. Empêche la modification de paramètres noyau. |
| ProtectKernelModules | ✓ | ✓ | Empêche le chargement de modules noyau (TM-032). |
| ProtectControlGroups | ✓ | ✓ | Empêche la modification de la hiérarchie cgroup. |
| ProtectKernelLogs | ✓ | ✓ | /proc/kallsyms masqué. Empêche les fuites d'adresses noyau. |
| ProtectClock | ✓ | ✓ | Empêche kexec et la modification de l'horloge système (TM-036). |

### Directives privilèges

| Directive | Agent | Exécuteur | Raison |
|---|---|---|---|
| NoNewPrivileges=yes | ✓ | ✓ | Empêche setuid/setgid/binaries. Un processus compromis ne peut pas s'élever. |
| RestrictSUIDSGID=yes | ✓ | ✓ | Empêche la création de fichiers SUID/SGID. |
| LockPersonality=yes | ✓ | ✓ | Empêche les changements d'ABI (par ex. passage en 32 bits pour contourner des filtres). |

### Directives réseau

| Directive | Agent | Exécuteur | Raison |
|---|---|---|---|
| RestrictAddressFamilies | AF_UNIX AF_INET AF_INET6 | **AF_UNIX seulement** | L'exécuteur n'a **AUCUN** accès réseau — c'est une propriété de sécurité critique : même compromis, il ne peut pas téléphoner à l'extérieur. L'agent a besoin d'IPv4/IPv6 pour HTTPS et d'AF_UNIX pour l'IPC. |

### Directives mémoire

| Directive | Agent | Exécuteur | Raison |
|---|---|---|---|
| MemoryDenyWriteExecute | ✓ | ✓ | W^X : pas de pages à la fois inscriptibles et exécutables. Empêche l'injection de code par modification de code en mémoire. |
| RestrictRealtime | ✓ | ✓ | Empêche l'ordonnancement temps réel (attaques par privation de ressources). |

## 3. Filtres seccomp (SystemCallFilter)

### Approche

L'approche **noire** (deny list) est utilisée pour le MVP car elle est
plus compatible (un syscall inconnu mais inoffensif continue de
fonctionner). La protection réelle vient de :
- `CapabilityBoundingSet` (vide ou minimal)
- `RestrictAddressFamilies` (pas de réseau pour l'exécuteur)
- `ProtectSystem=strict` (filesystem en lecture seule)

Une approche **blanche** (allow list) sera adoptée après les tests
d'intégration complets en VM (documentation des syscalls réellement
utilisés par chaque composant sous charge).

### Exécuteur : syscalls refusés

| Groupe | Raison |
|---|---|
| @network-io | Aucun réseau (socket AF_UNIX uniquement). |
| @obsolete | Syscalls obsolètes (compatibilité historique). |
| @mount | Pas de montage/démontage. |
| @debug | Pas de ptrace (TM-029). |
| @swap | Pas de gestion de swap. |
| SystemCallArchitectures=native | Bloque les appels syscall en mode compatibilité 32 bits. |

## 4. Limites de ressources

| Limite | Agent | Exécuteur | Raison |
|---|---|---|---|
| MemoryMax | 150 MB | 100 MB | TEST_STRATEGY §F : < 100 MB attendu. 150/100 MB = marge de sécurité. |
| CPUQuota | 10% | 20% | L'agent est majoritairement en attente (polling). L'exécuteur peut avoir des pics courts lors des commits. |
| LimitNOFILE | 4096 | 256 | L'agent parcourt des répertoires (besoin de FDs). L'exécuteur ouvre quelques fichiers à la fois. |
| LimitCORE | 0 | 0 | Pas de core dumps (fuite d'information potentielle). |
| TasksMax | — | 16 | L'exécuteur ne doit pas forker (traitement par thread, pas par processus). |

## 5. Revue et maintenance

- Ce document DOIT être mis à jour à chaque modification des unités.
- Les unités sont testées en VM (`tests/vm/scenarios/`) pour vérifier
  que les composants fonctionnent avec ces restrictions.
- Tout ajout de ReadWritePaths, de capability ou de syscall autorisé
  exige un ADR et une justification dans ce document.
