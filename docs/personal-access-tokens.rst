Personal and API access tokens
==============================

Epicrypt 3.0 provides a stateful personal/API-token profile for credentials that
users, service accounts, or automation can create and later revoke. The raw
credential is a purpose-isolated ``pat+jwt`` value, while authoritative token
metadata and revocation state live in the host application's durable
``PersonalAccessTokenStoreInterface`` implementation.

This is intentionally different from a self-contained long-lived JWT. A valid
signature is necessary but not sufficient: ``PersonalAccessTokenManager`` also
requires a matching active store record before accepting the credential.

Ownership and security model
----------------------------

Epicrypt owns:

- bounded token names, subjects, lifetimes, and abilities;
- ``pat+jwt`` issue and cryptographic verification;
- dedicated ``API_PERSONAL_TOKEN_SIGNING`` key-purpose isolation;
- authoritative record matching and active/revoked checks;
- exact ability checks and optional explicit ``*`` wildcard policy;
- list, single-token revoke, and subject-wide ``revokeAll()`` orchestration;
- optional coalesced ``last_used_at`` recording.

The host application owns:

- the durable PAT and optional usage-store implementations;
- authentication/authorization required before issuing, listing, or revoking a
  user's tokens;
- HTTP headers/routes and token presentation policy;
- database transaction/locking behavior;
- audit, rate limiting, naming policy, UI, and business authorization.

The raw PAT JWT is returned only at issue time. Never persist or log it. Persist
only the ``PersonalAccessTokenRecord`` fields required by the store contract.

Complete lifecycle: provision, issue, authorize, observe, and revoke
--------------------------------------------------------------------

The example below shows the complete application lifecycle. ``$patStore`` is a
production shared implementation of ``PersonalAccessTokenStoreInterface`` and
``$patUsageStore`` is an optional shared implementation of
``PersonalAccessTokenUsageStoreInterface``. They are application adapters; do
not replace them with process-local arrays in a horizontally scaled deployment.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenManager;
   use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenPolicy;
   use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
   use Infocyph\Epicrypt\Security\KeyPurpose;
   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\KeyRingEntry;
   use Infocyph\Epicrypt\Security\KeyStatus;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;

   // Deployment-time key provisioning. Keep the private key in a secret manager.
   $issuer = 'https://auth.example.com';
   $pair = sodium_crypto_sign_keypair();
   $privateKey = sodium_crypto_sign_secretkey($pair);
   $publicKey = sodium_crypto_sign_publickey($pair);
   $keyId = 'pat-2026-09';

   $publicKeys = new KeyRing([
       new KeyRingEntry(
           id: $keyId,
           key: $publicKey,
           status: KeyStatus::ACTIVE,
           purpose: KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
           algorithm: AsymmetricJwtAlgorithm::EDDSA->value,
           issuer: $issuer,
       ),
   ]);
   $signingKeys = new AsymmetricSigningKeySet(
       issuer: $issuer,
       activeKeyId: $keyId,
       privateKey: $privateKey,
       publicKeys: $publicKeys,
       algorithm: AsymmetricJwtAlgorithm::EDDSA,
       purpose: KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
   );

   $policy = new PersonalAccessTokenPolicy(
       audience: 'https://api.example.com',
       defaultLifetimeSeconds: 30 * 24 * 60 * 60,
       maximumLifetimeSeconds: 365 * 24 * 60 * 60,
       lastUsedWriteIntervalSeconds: 300,
   );
   $tokens = new PersonalAccessTokenManager(
       keys: $signingKeys,
       store: $patStore,
       policy: $policy,
       usageStore: $patUsageStore,
   );

   // 1. Issue after the host has authenticated and authorized token creation.
   $issue = $tokens->issue(
       subject: 'user-42',
       name: 'deployment-cli',
       abilities: ['releases:read', 'releases:deploy'],
       expiresAt: time() + 90 * 24 * 60 * 60,
   );
   $rawToken = $issue->token; // Show/send once over TLS; never store this value.
   $tokenId = $issue->record->tokenId; // Safe authoritative identifier to persist/display.

   // 2. Later, authenticate an API request carrying the raw token.
   $validation = $tokens->verify($presentedBearerToken);
   if (!$validation->accepted()) {
       throw new RuntimeException('Personal access token rejected.');
   }

   // 3. Enforce the exact capability required by this application operation.
   if (!$validation->allows('releases:deploy')) {
       throw new RuntimeException('Personal access token lacks the required ability.');
   }
   $authenticatedSubject = $validation->record?->subject;

   // 4. List metadata for the account-security UI. Raw credentials are absent.
   $activeTokens = $tokens->list('user-42');

   // 5. Revoke one credential by authoritative token ID + subject.
   $tokens->revoke($tokenId, 'user-42');
   if ($tokens->verify($rawToken)->accepted()) {
       throw new RuntimeException('Revoked personal access token remained active.');
   }

   // 6. A password reset, compromise response, account disablement, or explicit
   // "sign out all API tokens" action can revoke every PAT for the subject.
   $revokedCount = $tokens->revokeAll('user-42');

``verify()`` performs both JWT policy validation and authoritative record
matching. Application code should use the returned result rather than decoding
JWT claims independently. ``allows()`` is false unless the token is valid and
the requested ability is authorized.

Ability policy
--------------

Abilities are exact strings by default. A token with ``releases:read`` does not
implicitly receive ``releases:*`` or ``*`` semantics.

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenPolicy;
   use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenWildcardPolicy;

   $strict = new PersonalAccessTokenPolicy('https://api.example.com');

   $explicitWildcard = new PersonalAccessTokenPolicy(
       audience: 'https://api.example.com',
       wildcardPolicy: PersonalAccessTokenWildcardPolicy::STAR,
   );

With the default ``DISABLED`` policy, attempting to issue an ability set
containing ``*`` fails configuration validation. Enable wildcard semantics only
when the host application intentionally defines ``*`` as full authority.

Lifetime policy
---------------

``PersonalAccessTokenPolicy`` applies a default lifetime and a hard maximum.
Caller-requested ``expiresAt`` must be after issue time and inside that maximum.
The 3.0 defaults are 30 days for normal issuance and at most 365 days.

Keep PATs bounded even when they are revocable. Shorter lifetimes reduce the
impact of delayed revocation visibility or a stolen credential.

Optional last-used tracking
---------------------------

Configure ``lastUsedWriteIntervalSeconds`` only when a
``PersonalAccessTokenUsageStoreInterface`` is supplied. Successful verification
then calls the usage store's atomic ``touch()`` operation. The store must coalesce
writes so high request volume does not turn authentication into a write on every
request.

``PersonalAccessTokenValidationResult::lastUsedAt`` contains the effective
persisted usage timestamp when usage tracking is enabled. Usage telemetry must
not weaken the primary cryptographic and revocation decision.

Key rotation
------------

Use a ``KeyRing`` with one eligible active
``API_PERSONAL_TOKEN_SIGNING`` key and any still-valid fallback public keys.
New tokens are issued with the active key ID; existing tokens can remain
verifiable until their signing key is no longer eligible and their token
lifetime has ended.

Never reuse OAuth access-token, OIDC ID-token, authorization-code, refresh-token,
or unrelated application-signing keys for PATs. ``AsymmetricSigningKeySet``
rejects the wrong key purpose during manager construction.

Persistence and concurrency requirements
----------------------------------------

The host ``PersonalAccessTokenStoreInterface`` must provide shared authoritative
state across all accepting workers. In particular:

- token IDs are unique;
- ``create()`` does not store the raw JWT;
- ``find()`` and ``listForSubject()`` return exact authoritative metadata;
- ``revoke()`` is bound to exact token ID and subject;
- ``revokeAll()`` and concurrent issue for the same subject have a deterministic
  serialization point so a race cannot create an unexpectedly surviving token;
- a committed revocation is immediately visible to verification paths.

An ordinary stale cache must not report a token active after a successful
revocation. See :doc:`token-storage` for the complete persistence rules.

Application request pattern
---------------------------

A typical HTTP adapter performs these steps:

1. extract the bearer credential from the trusted header location;
2. reject malformed/oversized transport input before application logging;
3. call ``PersonalAccessTokenManager::verify()``;
4. reject any result for which ``accepted()`` is false;
5. call ``allows()`` for the operation-specific ability;
6. use ``result.record.subject`` as the authenticated principal identifier;
7. apply application/tenant authorization, rate limits, and audit policy;
8. never log the raw bearer token.

PAT verification proves the Epicrypt token and authoritative token record are
valid. It does not replace the application's resource-ownership, tenant, or
business authorization checks.
