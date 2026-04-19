Security Recommendations
========================

This page is the practical answer to:

**"Which Epicrypt option should I choose for a new application?"**

Quick Picks
-----------

If you are starting fresh, prefer these defaults:

- Password hashing: ``PasswordHasher`` with ``SecurityProfile::MODERN``
- Password upgrades: ``verifyAndRehash()``
- App payload encryption: ``DataProtection\StringProtector``
- Large file encryption: ``DataProtection\FileProtector``
- Envelope-style protected storage: ``DataProtection\EnvelopeProtector``
- API tokens with one shared secret: ``Token\Jwt\SymmetricJwt``
- API tokens with separate signer/verifier trust: ``Token\Jwt\AsymmetricJwt``
- Revocable random bearer tokens: ``Token\Opaque\OpaqueToken``
- Small signed action/reset payloads: ``Token\Payload\SignedPayload``
- Browser workflow tokens: ``Security`` domain helpers such as ``PasswordResetToken`` and ``SignedUrl``
- New ciphertext formats: modern ``DataProtection`` APIs

Public Surface First
--------------------

For new applications, start from these domains first:

- ``Password``
- ``Token``
- ``DataProtection``
- ``Security``

Treat these as lower-level or advanced:

- ``Crypto`` for direct primitive control

Choose the Right Tool
---------------------

Passwords
^^^^^^^^^

Use:

- ``PasswordHasher`` for stored user passwords
- ``PasswordStrength`` for quality feedback
- ``verifyAndRehash()`` when you want login-time hash upgrades

Prefer:

- ``SecurityProfile::MODERN``
- default Argon2id-based hashing

Avoid:

- custom password hashing logic
- storing app secrets as password hashes when you actually need reversible protection

Secrets and Stored Sensitive Values
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use:

- ``WrappedSecretManager`` for secrets that must be unwrapped later
- ``SecureSecretSerializer`` for structured secret-bearing data
- ``KeyRing`` plus rewrap helpers during rotation windows

Prefer:

- one active master secret
- short fallback windows for previous key versions

Protected Data
^^^^^^^^^^^^^^

Use:

- ``StringProtector`` for ordinary application payloads
- ``EnvelopeProtector`` when you want a structured encoded envelope
- ``FileProtector`` for large files and streaming-safe encryption
- ``FileProtector::reencryptWithAnyKey()`` when rotating protected files across key versions

Prefer:

- re-encrypting artifacts under the active key when fallback keys match
- ``decryptWithAnyKey()`` or ``reencryptWithAnyKey()`` only during rotation windows
- result helpers like ``decryptWithAnyKeyResult()`` when rotation code needs to know which key matched

Avoid:

- using low-level crypto primitives directly unless you really need them

Tokens
^^^^^^

Use:

- ``SymmetricJwt`` when issuer and verifier share one secret
- ``AsymmetricJwt`` when the signer should keep a private key and verifiers should only need public keys
- ``OpaqueToken`` when token contents should stay server-side
- ``SignedPayload`` for compact signed internal flows

Prefer:

- ``kid`` plus key-set mode when rotating JWT signing keys
- ``KeyRing``-based verification helpers during short transition windows
- ``verifyWithAnyKeyResult()`` when callers need to know whether a fallback key matched

Avoid:

- mixing symmetric and asymmetric expectations in one verification path
- exposing sensitive state in JWT claims when opaque tokens fit better

Crypto Primitives
^^^^^^^^^^^^^^^^^

Use:

- ``AeadCipher`` for authenticated encryption of short payloads
- ``SecretBoxCipher`` when you specifically want secretbox semantics
- ``SecretStream`` or ``FileProtector`` for large file workflows
- ``Mac`` for shared-secret integrity
- ``Signature`` for public/private signature verification

Prefer:

- ``AeadAlgorithm::XCHACHA20_POLY1305_IETF`` for new AEAD usage
- higher-level ``DataProtection`` APIs unless the primitive is truly what you need

Key Material and Derivation
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use:

- ``KeyMaterialGenerator`` for fresh random keys
- ``KeyDeriver`` for derived keys
- purpose-aware key generation helpers when available

Prefer:

- generated keys for encryption keys
- derived keys when the design specifically needs deterministic derivation
- explicit context/info separation for derived subkeys

Key Rotation
------------

Use key-ring helpers during planned key rollover.

Prefer this pattern:

1. issue new artifacts with the active key
2. keep decode/verify paths able to read active and fallback keys during rollout
3. re-encrypt or re-issue under the active key when a fallback key matches
4. remove fallback keys after the rollover window closes

In particular:

- prefer ``StringProtector`` and ``EnvelopeProtector`` for new protected data
- follow the key rotation cookbook for active-key and fallback-key rollout patterns

Binary vs Base64URL
-------------------

Most public Epicrypt APIs expect Base64URL strings by default.

Use explicit context flags only when you are intentionally passing raw binary values, for example:

- ``key_is_binary``
- ``nonce_is_binary``
- ``salt_is_binary``

When possible, keep one format per application boundary instead of mixing both styles in the same layer.

Simple Rule of Thumb
--------------------

- If a higher-level ``Password``, ``Security``, ``Token``, or ``DataProtection`` API fits your use case, choose it first.
- Reach for ``Crypto`` primitives only when you need direct cryptographic control.
- Prefer modern defaults and active-key rotation.
