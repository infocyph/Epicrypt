Migrating from Epicrypt 2.x to 3.0
==================================

Epicrypt 3.0 is a major API and architecture release. It deliberately removes
superseded development surfaces and introduces a transport-neutral OAuth/OIDC
and personal-token core, but it does **not** invent new persisted cryptographic
formats merely because the package major changes.

Runtime requirements
--------------------

Epicrypt 3.0 requires PHP 8.4 or later and the ``hash``, ``json``, ``openssl``
and ``sodium`` extensions. The asymmetric/PKI dependency is phpseclib 4.0.1 or
later.

``infocyph/pathwise`` is no longer a production dependency. Pathwise 4 is used
only by Epicrypt's development interoperability suite. Storage/framework code
opens its own streams and passes those streams to Epicrypt; Epicrypt does not
own global mounts, registries or application path policy.

Persisted compatibility
-----------------------

The following established Epicrypt 2.x formats remain readable/verifiable in
3.0 and are protected by frozen fixtures:

* ``ep2`` authenticated string/envelope payloads;
* ``ep2`` protected-file framing using XChaCha20-Poly1305 SecretStream;
* signed-payload v2 tokens.

Do not bulk-reencrypt durable data solely because the package major changed.
Rotate or renew values according to key lifecycle, policy or application needs.

Authentication credentials introduced or finalized during the unreleased 3.0
development cycle are different: there is no source/API compatibility promise
for superseded pre-release OAuth/refresh/PAT surfaces. Adopt the final
``Infocyph\Epicrypt\Auth`` contracts documented for the 3.0 release.

Stream-first file protection and hashing
----------------------------------------

``SecretStream``, ``FileProtector`` and ``FileHasher`` have native PHP stream
APIs. Existing local-path convenience methods use the stream core internally.
Caller-owned output streams are not transactionally published by Epicrypt; if a
failed multi-frame decrypt must never expose previously authenticated frames,
stage output in the storage/application layer. Local-path wrappers already
stage and atomically publish complete output.

Key material encoding
---------------------

``KeyMaterialGenerator`` no longer uses boolean encoding switches. Use
``KeyMaterialEncoding`` explicitly:

.. code-block:: php

   use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyMaterialEncoding;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $keys = new KeyMaterialGenerator();
   $storedSecret = $keys->forMasterSecret();
   $rawSecret = $keys->forMasterSecret(KeyMaterialEncoding::RAW);
   $hexSecret = $keys->forTokenSecret(KeyMaterialEncoding::HEX);

Requested lengths always refer to raw entropy bytes before encoding.

Removed duplicate generators
----------------------------

``Password\Secret\MasterSecretGenerator`` is removed. Use
``KeyMaterialGenerator::forMasterSecret()``.

``Generate\KeyMaterial\TokenMaterialGenerator`` is removed. Use
``RandomBytesGenerator::string()`` for generic opaque/random identifiers and
``KeyMaterialGenerator::forTokenSecret()`` for cryptographic signing/MAC
secrets.

Password hashing
----------------

Argon2id is the sole modern new-write password profile. Existing Argon2i and
bcrypt hashes remain verifiable because PHP identifies their algorithm from the
stored hash. A successful ``verifyAndRehash()`` can migrate them to Argon2id.
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

Epicrypt 3 is native phpseclib 4; there is no phpseclib 3/4 compatibility shim.
Public Epicrypt APIs do not expose phpseclib implementation objects.

PKI uses backend strengths rather than a lowest-common-denominator facade:
phpseclib 4 owns bounded X.509/CSR/PFX parsing/model validation while OpenSSL
remains the accelerated issuance, key-generation, purpose-aware chain
verification and interoperable PKCS#12 serialization backend. ``Pkcs12`` remains
the public PFX/PKCS#12 boundary.

Epicrypt 3 does not expose first-class CRL verification or CMS APIs. OCSP and
AIA network fetching also remain outside core.

JWT, JOSE and key rotation
--------------------------

Use ``PurposeToken`` for generic purpose-bound timed signed tokens instead of
application-local HMAC token codecs. It owns ``iat``/``exp``, optional ``nbf``,
purpose, token ID, optional subject, context binding and KeyRing-aware signing
and verification.

Signed URLs have a dedicated ``KeyPurpose::SIGNED_URL`` rotation domain.
Application subkeys should use ``KeyDeriver`` with stable purpose/context
identifiers rather than hand-written HMAC derivation.

Remote JWKS/OpenID discovery is explicit trusted configuration, never driven by
untrusted token ``jku``/``x5u``. Epicrypt bounds metadata/JWKS documents, cache
lifetimes, stale use and unknown-``kid`` refresh; the supplied HTTP client still
owns redirect and transport/DNS timeout policy as documented in
:doc:`remote-jose-security`.

OAuth/OIDC migration
--------------------

Epicrypt 3.0 now owns reusable OAuth/OIDC protocol mechanics that previously had
to be implemented in an application/framework layer. Hosts should remove local
reimplementations and adapt transport/persistence around these public services:

* ``OAuthAuthorizationRequestValidator`` for client/redirect/scope/PKCE request
  validation;
* ``OAuthAuthorizationCodeIssuer`` / ``OAuthAuthorizationCodeConsumer`` for the
  encrypted one-time authorization-code lifecycle;
* ``OAuthClientAuthenticator`` and strict ``private_key_jwt`` validation;
* ``OAuthTokenEndpoint`` for Authorization Code, Client Credentials and Refresh
  Token grant mechanics;
* ``OAuthAccessTokenService`` / resource validation for RFC 9068 access tokens;
* ``RefreshTokenManager`` for encrypted refresh artifacts plus authoritative
  rotation/reuse/revocation state;
* revocation, introspection, metadata/JWKS and DPoP services;
* OIDC request/interaction, ID-token, UserInfo and Discovery services;
* personal/API token manager/store contracts under ``Auth\Personal``.

The removed development-era ``Token\Opaque\RefreshToken*`` lifecycle is **not**
the Epicrypt 3.0 OAuth refresh API. Generic ``OpaqueToken`` remains available
for isolated high-entropy opaque identifiers.

Authentication persistence migration
------------------------------------

Do not carry forward a digest-only opaque refresh schema as if it were the 3.0
OAuth contract. Final refresh artifacts are compact JWE credentials; the raw JWE
is returned to the client and never persisted. After authenticated decryption,
Epicrypt passes ``RefreshTokenRecord`` to the application store. Persist the
record's token ID, family ID, authorization/grant state, issued/idle-expiration
state and consumed/replacement/revocation metadata required by the store
contract.

The final refresh invariants are:

* token IDs and family IDs are authenticated random identifiers, not raw tokens;
* current-state validation and replacement are atomic;
* consumed ancestors remain available through authorization lifetime for reuse
  detection;
* a reused ancestor revokes the complete family;
* client/DPoP/scope mismatches do not consume the legitimate token;
* scopes may only narrow;
* authorization-wide revocation reaches all families;
* stale active/revoked reads are not acceptable.

Likewise, raw authorization-code JWE and PAT JWT values are never stored.
Authorization-code consume, replay claims and security-sensitive revocation
reads must be shared/atomic across all accepting workers. See
:doc:`token-storage` for the complete adapter contract.

Framework/application ownership
-------------------------------

A dependent framework retains ownership of:

* HTTP routes and request/response adaptation;
* login/account selection/consent UI;
* principal/account repositories;
* DB/cache implementations of Epicrypt store interfaces;
* backend transactions/locking;
* sessions/cookies;
* application permission policy;
* rate limiting, audit and telemetry;
* environment/config/file loading and deployment key locations.

Do not reimplement PKCE, authorization-code semantics, refresh reuse detection,
OIDC nonce/hash rules, access-token verification, DPoP or PAT ability semantics
in the framework once it adopts Epicrypt 3.

Foundation adoption is intentionally **post-release** work. Epicrypt 3.0 must be
released independently first; only then should Foundation be rescanned against
the released public API and receive its DBLayer/HTTP adapters and persisted-state
migration where required.

Release validation
------------------

Before adopting 3.0 in a dependent application, run that application's complete
PHP 8.4/8.5 matrix against the released dependency graph. Epicrypt itself is
released only after its exact release commit passes the ordinary QA/analyzer,
security audit, independent interoperability, security-critical mutation,
parser/negative-vector, performance/persistent-runtime and public-API freeze
gates without skipped tests, lowered thresholds or release-only suppressions.
