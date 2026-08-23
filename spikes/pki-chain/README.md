# Spike PKI — sprint 2 (ISS-011)

Prototype **jetable** tranchant les points ouverts du spike ISS-006
(`docs/spikes/ISS-006-pki-tls.md`) avant implémentation réelle dans le
workspace :

1. chaîne racine→intermédiaire→client/serveur **Ed25519** (rcgen), profils
   contraints (EKU, path-length 0) ;
2. handshake **mTLS avec le backend ring** de rustls (signing Ed25519
   client : NON VÉRIFIÉ jusqu'ici) ;
3. **CRL** construite via `x509-cert 0.3 CrlBuilder`, signée par
   l'intermédiaire, **consommée par rustls** (révocation effective) ;
4. refus du client sans certificat (fail-closed de la vérification).

Exécution : `cargo test` ; contrôle du backend :
`cargo tree | grep -c aws-lc` (doit renvoyer 0).

Résultat : voir `docs/spikes/ISS-011-prototype-pki.md`.
