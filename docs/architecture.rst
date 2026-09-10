Architecture
============

Capability-First Model
----------------------

Epicrypt is organized by **responsibility**, not by backend engine.

Top-level capability domains:

- ``Auth``
- ``Certificate``
- ``Token``
- ``Crypto``
- ``DataProtection``
- ``Password``
- ``Integrity``
- ``Generate``
- ``Security``
- ``Exception``
- ``Internal``

``Auth`` owns the transport-neutral OAuth 2.1, OpenID Connect, DPoP, and
personal/API-token protocol core. ``Token`` remains the lower-level JWT/JWS/JWE,
JWK/JWKS, payload, and generic opaque-token capability used by authentication
and non-authentication consumers.

Core Rule
---------

- Top-level domain answers: **what is this for?**
- Backend namespace answers: **how is this implemented?**

Example:

- ``Certificate`` is the capability.
- ``Certificate\OpenSSL`` and ``Certificate\Sodium`` are backend implementations.

Named Backend Selection
-----------------------

When multiple backends satisfy the same responsibility, Epicrypt exposes named constructors:

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
   use Infocyph\Epicrypt\Certificate\KeyExchange;

   $keyExchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
   // or:
   $keyExchange = KeyExchange::forBackend(KeyExchangeBackend::OPENSSL);

Contracts and Ownership
-----------------------

Contracts live with the capability that owns the behavior.

Examples:

- ``Certificate\Contract\KeyExchangeInterface`` selects a key-exchange
  provider.
- ``Token\Jwt\JwtReplayStoreInterface`` owns atomic single-use and denylist
  state shared by JWT, OAuth client-assertion, and DPoP validation.
- ``Auth\OAuth\AuthorizationCodeStoreInterface`` owns authoritative one-time
  authorization-code state.
- ``Auth\OAuth\RefreshTokenStoreInterface`` owns durable transactional refresh
  rotation, reuse detection, family revocation, and authorization revocation.
- ``Auth\Personal\PersonalAccessTokenStoreInterface`` owns authoritative
  personal/API-token active and revoked state.

Persistence implementations remain application-owned. Epicrypt defines the
security contract and orchestration but does not silently substitute a
process-local store where cross-worker atomicity is required. Applications must
preserve the atomicity and visibility rules documented in :doc:`token-storage`.

Authentication Boundary
-----------------------

Epicrypt owns reusable protocol/security mechanics and typed results. Host
applications retain:

- HTTP routing and request/response serialization;
- login, account selection, and consent UI;
- principal/account repositories;
- concrete database/cache adapters and transaction/locking implementation;
- sessions and cookies;
- application authorization policy;
- rate limiting, audit, telemetry, and deployment configuration.

A host adapter may translate transport and persistence, but it must not
reinterpret redirect, PKCE, token, replay, revocation, or ability decisions
already made by Epicrypt.

Public vs Internal
------------------

- Capability entry/service classes are public API surface.
- ``Support`` and ``Internal`` classes are implementation details unless explicitly documented as public.
- ``Internal\SignedPayloadCodec`` is a shared internal primitive used across domains.
- Each public capability guide includes a complete-path integration workflow.
  ``Internal`` has no consumer example because applications must not depend on
  it directly.

Security Design Principles
--------------------------

Epicrypt follows:

- safe defaults;
- explicit inputs and outputs;
- deterministic validation;
- fail-closed behavior;
- versioned payload framing for sensitive formats;
- capability/purpose-isolated keys;
- bounded parsing and resource use;
- atomic authoritative state for one-time/revocable credentials;
- constant-time comparison for security checks where applicable.
