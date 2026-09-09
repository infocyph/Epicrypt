Migrating from Epicrypt 2.x to 3.0
==================================

Epicrypt 3.0 is a major API and architecture release. It deliberately removes
several duplicate or backend-coupled APIs, but it does **not** introduce a new
cryptographic wire format merely because the package major changed. Valid
Epicrypt 2.x protected values, protected files and signed-payload fixtures remain
part of the 3.0 compatibility suite.

Runtime requirements
--------------------

Epicrypt 3.0 requires PHP 8.4 or later and the ``hash``, ``json``, ``openssl``
and ``sodium`` extensions. The native asymmetric/PKI dependency is phpseclib
4.0.1 or later.

``infocyph/pathwise`` is no longer a production dependency. Pathwise 4 is used
only by Epicrypt's development interoperability suite. Applications that own a
Pathwise/Flysystem storage context should open the input/output streams and pass
those streams to Epicrypt; Epicrypt does not own global mounts, storage
registries or application path policy.

Persisted compatibility
-----------------------

The following 2.x formats remain readable/verifiable in 3.0 and are protected by
frozen fixtures:

* ``ep2`` authenticated string/envelope payloads;
* ``ep2`` protected-file framing using XChaCha20-Poly1305 SecretStream;
* signed-payload v2 tokens.

Do not bulk-reencrypt durable data solely because the package major changed.
Rotate or renew data according to key lifecycle, policy or application needs.

Stream-first file protection and hashing
----------------------------------------

``SecretStream``, ``FileProtector`` and ``FileHasher`` now have native PHP
stream APIs. Existing local-path convenience methods remain and use the stream
core internally.

Storage/framework code should resolve and open streams itself. Caller-owned
output streams are not transactionally published by Epicrypt; if a failed
multi-frame decrypt must never expose already-authenticated earlier frames,
stage the output in the storage/application layer. The local-path wrappers
already stage and atomically publish complete output.

Key material encoding
---------------------

``KeyMaterialGenerator`` no longer uses boolean encoding switches. Use
``KeyMaterialEncoding`` explicitly:

.. code-block:: php

   use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyMaterialEncoding;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $keys = new KeyMaterialGenerator();
   $storedSecret = $keys->forMasterSecret(); // Base64URL
   $rawSecret = $keys->forMasterSecret(KeyMaterialEncoding::RAW);
   $hexSecret = $keys->forTokenSecret(KeyMaterialEncoding::HEX);

Requested lengths always refer to raw entropy bytes before encoding.

Removed duplicate generators
----------------------------

``Password\Secret\MasterSecretGenerator`` is removed. Use
``KeyMaterialGenerator::forMasterSecret()``.

``Generate\KeyMaterial\TokenMaterialGenerator`` is removed. Use
``RandomBytesGenerator::string()`` for generic opaque/random token or identifier
text. Use ``KeyMaterialGenerator::forTokenSecret()`` when the value is a
cryptographic signing/MAC secret.

Password hashing
----------------

Argon2id is the sole modern new-write password profile. ``PasswordHashAlgorithm``
therefore exposes Argon2id and explicit bcrypt compatibility, not Argon2i.
Existing Argon2i hashes remain verifiable because PHP identifies the algorithm
from the stored hash. A default ``PasswordHasher::verifyAndRehash()`` call
migrates a successfully verified Argon2i or bcrypt hash to Argon2id.

This is a write-policy retirement, not a password-data migration requirement.
Never rehash without the user's plaintext password after successful
verification.

In-memory protected-value bounds
--------------------------------

Epicrypt 3 fails oversized compact protected values before expensive parsing or
cryptographic work:

* ``StringProtector`` plaintext: 16 MiB maximum;
* compact ``ep2`` payload: 24 MiB maximum;
* encoded protected metadata header: 32 KiB maximum;
* ``EnvelopeProtector`` plaintext: 8 MiB maximum.

Use the bounded-memory ``FileProtector`` stream API for larger content.

phpseclib 4 and PKI
-------------------

Epicrypt 3 is native phpseclib 4; there is no phpseclib 3/4 shim or dual-major
namespace probing. Public Epicrypt APIs do not expose phpseclib implementation
objects.

PKI deliberately uses backend strengths rather than a lowest-common-denominator
facade: phpseclib 4 owns bounded X.509/CSR/PFX parsing and model validation,
while OpenSSL remains the accelerated issuance, key-generation,
purpose-aware-chain-verification and interoperable PKCS#12 serialization
backend. ``Pkcs12`` remains the public PFX/PKCS#12 boundary.

Epicrypt 3 does not expose first-class CRL verification or CMS APIs. CRL
verification would otherwise require ambiguous process-global issuer state in
the available convenience path, and no current consumer justifies expanding the
CMS parser/interoperability surface. OCSP and AIA network fetching also remain
outside core.

Tokens, signed URLs and key rotation
------------------------------------

Use ``PurposeToken`` for generic purpose-bound timed signed tokens instead of
application-local HMAC token codecs. It owns ``iat``/``exp``, optional ``nbf``,
purpose, token ID, optional subject, context binding and KeyRing-aware signing
and verification.

Signed URLs have a dedicated ``KeyPurpose::SIGNED_URL`` rotation domain.
KeyRing-backed URLs carry an authenticated key selector; the raw-secret mode
remains available for simple single-key applications and retains its existing
wire format.

For application subkeys, replace hand-written HMAC derivation with
``KeyDeriver`` and stable purpose/context identifiers. Persist those derivation
identifiers as part of the long-lived key contract.

Remote JOSE and OAuth lifecycle
-------------------------------

Remote JWKS/OpenID discovery is explicit configuration, never driven by an
untrusted token ``jku``/``x5u``. Redirect behavior, DNS/IP policy and network
timeouts remain responsibilities of the supplied HTTP client. Epicrypt bounds
metadata/JWKS documents, cache lifetimes, stale use and unknown-``kid`` refresh.

Refresh-token rotation requires a durable application implementation of
``RefreshTokenStoreInterface`` with one atomic consume-and-replace transaction.
Store digests, never raw refresh tokens. DPoP replay storage must also be atomic
across workers.

Foundation-oriented migration
-----------------------------

Framework/application code should retain application ownership of configuration,
filesystem paths, environment-file mutation, HTTP behavior, storage
transactions, auditing and domain persistence. Generic cryptographic mechanics
can move to Epicrypt:

* application-local signed/timed HMAC codecs -> ``PurposeToken``;
* raw application subkey HMAC derivation -> ``KeyDeriver``;
* ad-hoc random secret generation -> ``KeyMaterialGenerator``;
* signing-key readiness/JWKS coherence -> Epicrypt signing-key-set and JOSE
  primitives;
* file crypto over Pathwise -> storage-owned streams passed to ``FileProtector``.

Release validation
------------------

Before adopting 3.0 in a dependent application, run its full PHP 8.4/8.5 test
matrix with the real dependency graph. In particular, applications using
Pathwise 4 should confirm that Epicrypt appears without Pathwise in the
production dependency tree and that storage contexts remain application-owned.
