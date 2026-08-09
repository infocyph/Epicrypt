Security recommendations
========================

* Prefer high-level DataProtection services over assembling primitives.
* Generate keys with CSPRNG-backed APIs and keep them outside source control.
* Treat purpose, AAD, key purpose, algorithm, and issuer as distinct boundaries.
* Use ``KeyRing`` for rotation; never bypass it by extracting raw key maps.
* Fix JWT algorithms and types in verifier configuration.
* Use atomic replay storage for single-use JWTs and a transactional
  ``RefreshTokenStoreInterface`` for refresh-token rotation.
* Preserve existing file destinations when decryption fails.
* Use Argon2id for new password hashes.
* Use only the integrity algorithm allowlist.
* Obtain an independent security review before a stable release.
