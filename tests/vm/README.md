# Harnais VM de laboratoire (ISS-005)

VM Fedora Cloud 44 **jetable et reproductible** pour les tests
d'intégration, les scénarios d'auto-blocage (catégorie D) et les
vérifications empiriques sur fapolicyd (memfd, objet supprimé — spike
ISS-008, items NON VÉRIFIÉ).

## Usage

```bash
bin/fetch-image.sh   # télécharge l'image F44 + vérifie SHA-256 (CHECKSUM officiel)
bin/run-vm.sh        # démarre la VM (overlay 40 Go, rien d'exposé hors de 127.0.0.1)
bin/wait-ssh.sh      # attend que SSH réponde (1-3 min au premier démarrage)
bin/vm-ssh.sh bash < scenarios/smoke.sh   # exécute un scénario DANS la VM
bin/vm-ssh.sh        # session interactive
bin/stop-vm.sh       # arrêt propre puis forcé si besoin
bin/reset-vm.sh      # repart d'un état neuf (supprime l'overlay uniquement)
```

## Choix techniques (DEC-17, provisoire)

- **QEMU en mode utilisateur** (pas de libvirt, pas de root, pas de démon) :
  raison — l'hôte de développement n'a pas `virtqemud` actif ni
  `virt-install` ; ce harnais fonctionne sans privilège aucun. Un backend
  libvirt (pour Testing Farm / CI multi-VM) pourra être ajouté plus tard
  derrière les mêmes sous-commandes.
- Réseau SLIRP : **seul le port 22 de la VM est joignable**, via
  `127.0.0.1:2222` (variable `VIGILE_VM_SSH_PORT`). Aucun port exposé sur
  le réseau local.
- État mutable isolé dans `.state/` (ignoré par git) : image de base,
  overlay, seed cloud-init, clé SSH **jetable**, console, known_hosts.

## Règles de sécurité du laboratoire

1. fapolicyd peut être **installé** dans la VM mais **jamais démarré ni
   activé** par un scénario de la phase 1 (validation hors ligne
   `--check-rules` uniquement) — aucune politique bloquante.
2. Aucun secret réel dans les VM (clés jetables régénérables).
3. Les scénarios sont idempotents et rejouables après `reset-vm.sh`.

## Limites connues

- Le CHECKSUM de l'image est **vérifié par signature OpenPGP** (clés Fedora
  locales de l'hôte) puis le SHA-256 de l'image contre ce CHECKSUM signé ;
  sur un hôte sans clé Fedora, la vérification GPG est impossible et le
  script échoue explicitement (jamais de contournement silencieux).
- Un seul seed au premier démarrage : après `reset-vm.sh`, tout est neuf
  (c'est le but) ; le seed reste monté mais cloud-init ne rejoue pas.
- Pas de snapshot intégré pour l'instant (à venir avec les scénarios de
  transaction interrompue : catégorie D/chaos).
- Premier retour d'expérience (2026-08-21) : boot → SSH en ~10 s (KVM),
  scénario smoke complet (installation fapolicyd 2.0-1.fc44 + validation
  hors ligne `--check-rules`, service jamais démarré) passé avec succès.
