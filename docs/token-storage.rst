Authentication persistence contracts
====================================

Epicrypt authentication state crosses process and machine boundaries. Production
adapters must therefore use shared durable storage with database/coordination
semantics strong enough to preserve one-time use, revocation and replay rules.
Epicrypt intentionally ships no process-local production fallback.

The host application implements Epicrypt's public store interfaces. Raw
authorization-code JWE, refresh-token JWE and personal-access-token JWT values
must never be persisted by those stores.

Refresh-token state
-------------------

The 3.0 refresh lifecycle lives under ``Infocyph\Epicrypt\Auth\OAuth``.

``RefreshTokenManager``
   Encrypts/decrypts refresh artifacts and coordinates issue, inspect, rotate,
   family revocation and authorization-wide revocation.

``RefreshTokenGrant``
   Immutable authorization state: authorization ID, subject, client, audiences,
   effective scopes, absolute authorization expiration and optional DPoP JWK
   thumbprint.

``RefreshTokenRecord``
   Authenticated state extracted from the JWE: 192-bit Base64URL token ID,
   256-bit family ID, grant, issued-at and idle-expiration timestamps.

``RefreshTokenStoreInterface``
   Durable extension point for create, inspect, atomic rotate, family revocation
   and authorization-wide revocation. The interface receives authenticated
   records, never the raw JWE.

``RefreshTokenRotationResult`` / ``RefreshTokenRotationStatus``
   ``ROTATED`` carries the replacement raw token and effective grant. Failures
   do not expose replacement material.

Adapter conformance
-------------------

Copy or extend the repository's refresh-store conformance fixtures in the host
adapter test suite and execute them against the actual production database.
Also run a genuinely concurrent two-transaction rotation test. An in-memory
double can validate contract logic but cannot prove database locking/isolation.

The store must preserve these invariants:

- ``token_id`` is globally unique for retained refresh history;
- ``family_id`` identifies one rotation family;
- the persisted current record exactly matches the authenticated JWE record
  before mutation;
- consumed history remains retained through authorization expiration so reuse of
  any ancestor can revoke the family;
- client or sender-binding mismatch never consumes the legitimate token;
- requested scopes may remain equal or narrow, never expand;
- replacement insertion and current-token consumption are one atomic operation;
- a replacement token-ID collision returns ``CONFLICT`` without consuming the
  current token;
- reuse of a consumed token revokes the family before ``REUSED`` is returned;
- family/authorization revocation becomes visible to every worker immediately.

Illustrative relational model
-----------------------------

The exact schema belongs to the host application. This PostgreSQL-shaped model
shows the required state; JSON columns may be normalized differently.

.. code-block:: sql

   CREATE TABLE oauth_refresh_families (
       family_id         varchar(43) PRIMARY KEY,
       authorization_id  varchar(255) NOT NULL,
       subject            varchar(255) NOT NULL,
       client_id          varchar(255) NOT NULL,
       audiences          jsonb NOT NULL,
       absolute_expires_at bigint NOT NULL,
       dpop_jkt           varchar(43),
       revoked_at         bigint
   );

   CREATE TABLE oauth_refresh_tokens (
       token_id           varchar(32) PRIMARY KEY,
       family_id          varchar(43) NOT NULL REFERENCES oauth_refresh_families(family_id),
       scopes             jsonb NOT NULL,
       issued_at          bigint NOT NULL,
       idle_expires_at    bigint NOT NULL,
       consumed_at        bigint,
       replacement_id     varchar(32)
   );

   CREATE INDEX oauth_refresh_families_authorization
       ON oauth_refresh_families (authorization_id);
   CREATE INDEX oauth_refresh_tokens_family
       ON oauth_refresh_tokens (family_id);

The token ID and family ID are authenticated random identifiers carried inside
the encrypted refresh artifact. They are not raw refresh tokens and they are not
digests of the artifact. Never add a column containing the compact JWE itself.

Atomic refresh rotation
-----------------------

Implement ``RefreshTokenStoreInterface::rotate()`` as one serializable or
transactionally equivalent decision:

1. Locate ``current.tokenId`` and lock the current/family state (or use an
   equivalent linearizable compare-and-swap primitive).
2. Verify persisted current state exactly matches ``current``. A forged/stale
   record cannot select a different authorization or family.
3. If the family is revoked, return ``REVOKED``. If the current record is
   already consumed, revoke the family and return ``REUSED``.
4. Evaluate absolute/idle expiration according to the interface contract.
5. Compare client ID and DPoP thumbprint before consuming state.
6. Verify ``replacement`` preserves family, authorization, subject, client,
   audiences, absolute expiration and sender binding; its scopes may only
   narrow.
7. Insert ``replacement.tokenId``. A uniqueness collision returns ``CONFLICT``
   without consuming current.
8. Mark current consumed and link the replacement in the same transaction.
9. Commit, then return ``ROTATED``.

Never implement this as an unlocked read followed by independent updates. Two
concurrent refresh requests must not both receive active successors.

Authorization-code storage
--------------------------

``AuthorizationCodeStoreInterface`` is authoritative for one-time code state.
The compact authorization-code JWE is returned only to the client; storage keeps
the authenticated metadata required to prove exact client, redirect, PKCE,
authorization and expiry state.

The consume operation must be atomic. Invalid client/redirect/PKCE presentations
must not burn a valid code, while two valid concurrent presentations must have
exactly one winner.

OAuth authorization and access-token status
-------------------------------------------

``OAuthAuthorizationStoreInterface`` owns approved authorization active/revoked
state. Revocation must be visible before new access/refresh issuance can
continue.

``OAuthAccessTokenStatusStoreInterface`` is optional deployment policy. When
configured, it is authoritative ``jti`` state used for immediate access-token
revocation in addition to normal short JWT expiration. Do not place an ordinary
stale cache in front of an authoritative revocation read.

Personal/API token state
------------------------

``PersonalAccessTokenStoreInterface`` owns metadata for ``pat+jwt`` tokens.
Persist token ID, subject, abilities, timestamps and revocation state, but never
the raw JWT. Verification combines JWT cryptographic/policy validation with the
authoritative record.

An optional ``PersonalAccessTokenUsageStoreInterface`` may coalesce last-used
updates. Usage telemetry must not become an availability dependency for the
cryptographic/revocation decision unless the host intentionally chooses that
policy.

JWT, DPoP and client-assertion replay
-------------------------------------

``JwtReplayStoreInterface`` is deliberately shared by one-time JWT policies,
DPoP proofs and OAuth client assertions.

``consume(namespace, tokenId, expiresAt)``
   Atomically claim a replay key if absent and return ``true`` exactly once.

``isRevoked(namespace, tokenId, expiresAt)``
   Non-consuming revocation lookup for repeatable JWT policies.

The namespace supplied by Epicrypt is part of the security domain. Store it
with the token ID; do not collapse unrelated token classes into one identifier
space. Retain state through the supplied expiration and clean it only after the
credential can no longer be accepted.

Caching and multi-process rules
-------------------------------

Security-sensitive active/revoked/consumed state is not ordinary cache data.
Adapters may cache immutable registration or public metadata where policy
allows, but they must not serve stale active state after a revocation/consume
commit.

For horizontally scaled deployments, use one of:

- a database transaction with row/advisory locking;
- serializable isolation;
- a compare-and-swap primitive with equivalent correctness;
- another linearizable coordination mechanism whose failure behavior is tested.

A PHP mutex, APCu entry, process-local array or local filesystem lock cannot
provide distributed token correctness by itself.

Deployment checklist
--------------------

- Never persist or log raw authorization codes, refresh tokens, access tokens,
  PAT JWTs, client assertions or DPoP proofs.
- Enforce token/family uniqueness in durable storage, not only in PHP.
- Preserve consumed refresh/code history for the full period required by the
  public store contract.
- Make rotation/consume/reuse/revocation atomic across workers.
- Keep client/sender/scope mismatch paths non-consuming.
- Treat refresh reuse as a security event while returning uniform protocol
  errors to the client.
- Revoke authorization-wide refresh families after account disablement,
  credential compromise or authorization withdrawal according to host policy.
- Use short-lived access tokens even when authoritative status/revocation is
  enabled.
- Run the host adapter's conformance and real concurrent transaction tests on
  every supported database/runtime combination.
