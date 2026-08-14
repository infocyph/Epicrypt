Token persistence contracts
===========================

JWT replay state and OAuth refresh tokens cross process and machine boundaries.
They therefore require application-provided shared storage. Epicrypt does not
provide a process-local production fallback because it could not enforce
single use or family revocation across workers.

Public refresh-token types
--------------------------

``RefreshTokenManager``
   Issues, rotates and revokes refresh tokens. It generates the secrets and
   stores only their digests through the configured store.

``RefreshTokenGrant``
   Immutable authorization state: grant ID, subject, client, audiences,
   scopes, absolute expiration and optional DPoP SHA-256 JWK thumbprint.

``RefreshTokenRecord``
   The validated persistence record supplied when a new token family is
   created.

``RefreshTokenStoreInterface``
   The application extension point for durable creation, atomic rotation,
   family revocation and grant-wide revocation.

``RefreshTokenRotationResult`` and ``RefreshTokenRotationStatus``
   The result returned to the authorization server. ``ROTATED`` includes the
   replacement token and effective grant. All other statuses contain neither.

Adapter conformance
-------------------

Copy or extend ``tests/Support/RefreshTokenStoreConformance.php`` in the host
application's integration-test suite and implement ``newStore()`` with a fresh
adapter connected to the real production database engine. The reusable suite
covers creation uniqueness, atomic winner/loser rotation, retained ancestor
reuse, family and grant revocation, client and DPoP binding, scope narrowing,
idle/absolute expiry, and replacement-digest conflicts. Also run a genuinely
concurrent two-transaction test using the database isolation/locking strategy
chosen by the host; an in-memory double cannot prove database concurrency.

Recommended relational model
----------------------------

Keep grants, families and token history separate. The following PostgreSQL
shape is illustrative; adapt names and timestamp types to the application.

.. code-block:: sql

   CREATE TABLE oauth_refresh_grants (
       id                 varchar(128) PRIMARY KEY,
       subject            varchar(255) NOT NULL,
       client_id          varchar(255) NOT NULL,
       audiences          jsonb NOT NULL,
       scopes             jsonb NOT NULL,
       absolute_expires_at bigint NOT NULL,
       dpop_jkt           char(43)
   );

   CREATE TABLE oauth_refresh_families (
       id          char(43) PRIMARY KEY,
       grant_id    varchar(128) NOT NULL REFERENCES oauth_refresh_grants(id),
       revoked_at  bigint
   );

   CREATE TABLE oauth_refresh_tokens (
       digest              char(64) PRIMARY KEY,
       family_id           char(43) NOT NULL REFERENCES oauth_refresh_families(id),
       effective_scopes     jsonb NOT NULL,
       issued_at           bigint NOT NULL,
       idle_expires_at     bigint NOT NULL,
       consumed_at         bigint,
       replacement_digest char(64)
   );

   CREATE INDEX oauth_refresh_families_grant
       ON oauth_refresh_families (grant_id);
   CREATE INDEX oauth_refresh_tokens_family
       ON oauth_refresh_tokens (family_id);

``digest`` is the lowercase 256-bit digest supplied by Epicrypt, not the raw
refresh token. ``effective_scopes`` starts with the grant scopes and is copied
or narrowed for each successor without expanding another family. Retain
consumed token rows until the grant expires so an old ancestor can still
trigger family-wide reuse detection.

Atomic rotation sequence
------------------------

Implement ``RefreshTokenStoreInterface::rotate()`` as one transaction:

1. Select the current token, family and grant by digest and lock the family and
   token rows. A compare-and-swap implementation providing the same guarantees
   is also valid.
2. If the current digest does not exist, return ``INVALID``. If its family is
   revoked, return ``REVOKED``.
3. If the token was already consumed, set the family's ``revoked_at`` before
   committing and return ``REUSED``.
4. Check absolute and idle expiration, client binding, DPoP thumbprint and
   requested scopes before consuming the legitimate token. A binding or scope
   mismatch must not consume it.
5. Ensure every requested scope was present in the current token's effective
   scopes. Copy the narrowed scope set into the successor authorization state;
   escalation is ``SCOPE_MISMATCH``.
6. Insert the replacement digest with the same family ID, the current time and
   ``min(absolute expiration, now + idle lifetime)``. A unique-key collision is
   ``CONFLICT``.
7. Mark the current token consumed, record the replacement digest and commit.
   Return ``ROTATED`` with the effective grant.

Never implement rotation as an unlocked read followed by independent updates.
Two concurrent requests must not both receive active successor tokens.

Authorization endpoint integration
----------------------------------

The authorization server should authenticate the client, verify any DPoP proof
and then rotate the refresh token. Use only the verified proof thumbprint.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\DpopProof;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRotationStatus;

   $proof = new DpopProof()->verifyResult(
       $dpopHeader,
       'POST',
       'https://auth.example.com/oauth/token',
       AsymmetricJwtAlgorithm::EDDSA,
       $sharedReplayStore,
       nonce: $serverNonce,
   );

   $result = $refreshTokens->rotate(
       $presentedRefreshToken,
       $authenticatedClientId,
       $proof['keyThumbprint'],
       requestedScopes: $requestedScopes,
   );

   if (!$result->rotated) {
       if ($result->status === RefreshTokenRotationStatus::REUSED) {
           $securityEvents->refreshTokenFamilyReuseDetected();
       }

       // Return the same OAuth error for every presentation failure.
       throw new RuntimeException('invalid_grant');
   }

   $accessToken = $accessTokenIssuer->issueForGrant($result->grant);
   $replacementRefreshToken = $result->token;

Do not derive a DPoP thumbprint from an unverified header. When a grant is not
DPoP-bound, pass ``null``; when it is bound, a missing or different thumbprint
returns ``SENDER_MISMATCH`` without consuming the token.

JWT replay and denylist store
-----------------------------

``JwtReplayStoreInterface`` has two deliberately different operations:

``consume(issuer, jwtId, expiresAt)``
   Atomically insert a replay key if absent. Return ``true`` exactly once. Use
   this for ``SINGLE_USE`` JWTs and DPoP proofs.

``isRevoked(issuer, jwtId, expiresAt)``
   Perform a non-consuming lookup. Return ``true`` only after the application
   has denylisted the token. Use this for repeatable ``DENYLIST`` access tokens.

Namespace storage keys by issuer and JWT ID, retain them through token expiry,
and use the supplied expiration for bounded cleanup. Signature, header, claim
and time validation happen before either storage operation.

Deployment checklist
--------------------

- Store digests only; redact tokens, authorization headers and DPoP proofs from
  logs and traces.
- Enforce unique digest and family identifiers at the database layer.
- Use the database server's transaction and locking guarantees, not a PHP
  process mutex.
- Retain consumed history until absolute grant expiration.
- Revoke every family for a grant after password change, account disablement or
  authorization withdrawal.
- Map presentation failures uniformly to ``invalid_grant``.
- Monitor ``REUSED`` as a security event without returning extra detail to the
  client.
- Use short-lived access tokens even when refresh-token rotation is enabled.
