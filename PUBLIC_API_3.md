# Epicrypt 3.0 Public API Contract

This document freezes the intended public surface and ownership decisions for the Epicrypt 3.0 major release. Source/API compatibility with intermediate pre-release Epicrypt 3 development snapshots is not provided. Persisted cryptographic compatibility is separate and remains supported where explicitly stated below.

## Product boundary

Epicrypt 3.0 is a capability-first PHP security toolkit and transport-neutral authentication protocol core.

Epicrypt owns generic cryptographic mechanics, JOSE/JWK/JWKS policy, and transport-neutral OAuth 2.1, OpenID Connect 1.0, DPoP, and personal/API-token protocol mechanics. Host applications own HTTP routing/adaptation, login and consent UI, account/principal repositories, concrete persistence adapters and transaction/locking implementation, sessions/cookies, application authorization policy, rate limiting, audit/telemetry, and deployment configuration.

A host may adapt transport and persistence but must not reimplement protocol security decisions already represented by the public Epicrypt API.

## Core/runtime surface

| Surface | 3.0 contract |
| --- | --- |
| `Crypto\SecretStream` | Stream-native API is core; local-path convenience remains. |
| `DataProtection\FileProtector` | Stream-native core plus atomic local-path convenience. |
| `Integrity\FileHasher` | Stream-native hashing core plus local-path convenience. |
| Pathwise types/dependency | Not part of the production API or dependency graph. |
| `DataProtection\ProtectionMetadata` | Metadata-only protection result is public. |
| phpseclib | Native phpseclib 4; implementation objects are not exposed in public contracts. |
| `Certificate\CertificateInspector` / `CsrInspector` | Public bounded backend-neutral inspection. |
| `Certificate\CertificateChainVerifier` | Explicit trust/purpose verification. |
| first-class CRL/CMS | Not part of 3.0. |
| `Generate\KeyMaterial\KeyMaterialGenerator` | Canonical key-material generator with explicit `KeyMaterialEncoding`. |
| `Generate\RandomBytesGenerator` | Generic secure random bytes/identifiers. |
| `Generate\KeyMaterial\KeyDeriver` | Purpose/context-labelled subkey derivation. |
| `Security\KeyPurpose::SIGNED_URL` | Dedicated signed-URL key domain. |
| `Security\AsymmetricSigningKeySet` | Signing-key readiness, coherence, eligibility and public JWKS validation. |
| `Token\Payload\PurposeToken` | Generic purpose-bound timed signed token mechanics. |

### Removed/replaced core surfaces

- `Password\Secret\MasterSecretGenerator` → `Generate\KeyMaterial\KeyMaterialGenerator::forMasterSecret()`.
- `Generate\KeyMaterial\TokenMaterialGenerator` → `Generate\RandomBytesGenerator::string()` or `KeyMaterialGenerator::forTokenSecret()`.
- boolean `KeyMaterialGenerator` output switches → explicit `KeyMaterialEncoding`.
- `PasswordHashAlgorithm::ARGON2I` is not a new-write selector; established Argon2i hashes remain verification/rehash compatible.
- phpseclib 3 implementation namespaces are not supported by the 3.0 implementation.

## Authentication token classes and key isolation

Epicrypt exposes distinct authentication token classes and binds them to dedicated cryptographic purposes. Authorization-code protection, refresh-token protection, OAuth access-token signing, OIDC ID-token signing, personal/API-token signing and other unrelated signing/protection domains must not be silently interchangeable.

The shared hard ceilings used by OAuth/OIDC/PAT processing are internal implementation policy; callers receive public typed validation/results rather than a mutable global policy registry.

## OAuth client and client-authentication surface

The 3.0 public OAuth client surface includes:

- `Auth\OAuth\OAuthClient`;
- `OAuthClientType`;
- `OAuthGrantType`;
- `OAuthClientAuthenticationMethod`;
- `OAuthClientSecret`;
- `OAuthClientKeySet`;
- `OAuthClientStoreInterface`;
- `OAuthClientAuthenticator`;
- `OAuthClientAssertionValidator` and typed assertion result/status values.

Runtime client registration is an immutable/read-only protocol snapshot. Secret credentials are one-way verification material. `private_key_jwt` trusts only explicitly registered public asymmetric keys; embedded `jwk`, remote `jku`, or `x5*` token locators cannot select trust material. Assertions are bounded by identity, audience, time, algorithm/key and replay policy.

`JwtReplayStoreInterface` is the reusable replay contract; Epicrypt does not add an OAuth-specific duplicate.

## OAuth authorization surface

The 3.0 authorization surface includes:

- `OAuthAuthorizationRequest` / `OAuthAuthorizationResult`;
- `OAuthErrorCode` / `OAuthProtocolError`;
- `OAuthAuthorizationRequestValidator`;
- `OAuthAuthorizationAudienceResolverInterface`;
- `OAuthSingleAudienceResolver`;
- `OAuthAuthorizationInteractionRequirement`;
- `OAuthAuthorizationInteraction`;
- `OAuthAuthorizationApproval`;
- `OAuthAuthorizationCodeIssuer`;
- `OAuthAuthorizationCodeIssueResult`;
- `OAuthAuthorizationCodeConsumer`;
- `OAuthAuthorizationCodeConsumeResult` / `OAuthAuthorizationCodeConsumeStatus`;
- `OAuthEndpointCapability` / `OAuthEndpointCapabilityCatalog`.

The validator accepts a transport-neutral parameter map in which a scalar represents one occurrence and a list preserves repeated occurrences. Repeated singleton OAuth parameters are rejected instead of being silently collapsed by a framework adapter.

A redirect becomes eligible for protocol-error redirection only after exact registration validation, or selection of the sole registered redirect when omission is permitted. Unknown/disabled clients, ambiguous omitted redirects, and redirect mismatches never receive a redirect target.

Authorization Code is the supported authorization response and PKCE `S256` is mandatory. Approval may narrow scopes but cannot widen the validated request. Successful authorization response parameters include RFC 9207 `iss`; safe redirectable errors can include the same issuer and validated state.

## Authorization-code artifact and persistence contract

The authorization-code artifact family includes `AuthorizationCode`, `AuthorizationCodeArtifact`, `AuthorizationCodeRecord`, `AuthorizationCodeStoreInterface` and the typed consume services/results.

The raw authorization-code JWE is never persisted. Persistence uses authenticated token identity plus exact canonical authorization state. Cryptographic decryption alone does not establish one-time use: `AuthorizationCodeStoreInterface` is authoritative for atomic consume/replay state.

Wrong client, redirect, PKCE or other binding attempts must not consume the legitimate code. Production store adapters must provide linearizable/transactionally equivalent one-winner semantics across all accepting workers.

## Approved authorization and access-token status contracts

The public authoritative-state contracts include:

- `OAuthAuthorizationRecord` / `OAuthAuthorizationStoreInterface`;
- `OAuthAccessTokenStatusRecord` / `OAuthAccessTokenStatusStoreInterface`.

Consent-history persistence remains application policy and is intentionally not duplicated by Epicrypt. The optional access-token status store allows a host to require authoritative JWT `jti` activity/revocation state in addition to cryptographic validation.

Security-sensitive authoritative reads must not return stale active records after a committed revocation/disablement.

## OAuth token endpoint and lifecycle surface

The final token/lifecycle surface includes:

- `OAuthTokenEndpoint`;
- `OAuthTokenResponse` / `OAuthTokenResult`;
- `OAuthAccessTokenService`;
- `OAuthAccessTokenInspector`;
- `OAuthResourceAccessTokenValidator`;
- `OAuthRevocationEndpoint` / `OAuthRevocationResult`;
- `OAuthIntrospectionEndpoint` / `OAuthIntrospectionResponse` / `OAuthIntrospectionResult`;
- `OAuthAuthorizationServerMetadata`;
- `OAuthJwksPublisher`;
- `OAuthDpopContext` / `OAuthDpopValidator`.

Supported grant mechanics are Authorization Code + mandatory PKCE S256, Client Credentials, and Refresh Token. Access tokens use the RFC 9068 JWT profile. Revocation follows the RFC 7009 non-oracular contract, introspection follows the protected RFC 7662 contract, metadata is capability-accurate, and DPoP validation/binding follows the supported RFC 9449 profile.

Epicrypt exposes protocol/core mechanics, not HTTP routes.

## Refresh-token surface and persistence contract

The final OAuth refresh surface is under `Auth\OAuth` and includes:

- `RefreshTokenArtifact`;
- `RefreshTokenGrant`;
- `RefreshTokenRecord`;
- `RefreshTokenStoreInterface`;
- `RefreshTokenManager`;
- typed result/status values for issue/rotation/reuse/revocation behavior.

The old refresh-specific `Token\Opaque\RefreshToken*` development lifecycle is removed. Generic `Token\Opaque\OpaqueToken` remains available only as a generic high-entropy opaque-token primitive.

Raw refresh JWE is never persisted and no digest of the raw JWE is required. Authenticated artifact identity/family/authorization state drives the authoritative store. Rotation must atomically consume/replace current state, consumed ancestors remain sufficient for reuse detection through the required authorization lifetime, reuse revokes the family, scopes only narrow, and client/sender mismatches do not consume the legitimate credential.

## OpenID Connect provider surface

Epicrypt 3.0 supports the OpenID Connect Authorization Code profile through public types including:

- `Auth\Oidc\OpenIdAuthorizationRequest` and its validator/interaction model;
- `OpenIdPrompt` and related typed request values;
- `OpenIdIdTokenIssuer` / `OpenIdIdTokenIssue`;
- `OpenIdTokenResponseExtension`;
- `OpenIdSubjectIdentifierProviderInterface` / `OpenIdSubjectType`;
- `OpenIdClaimsProviderInterface`;
- `OpenIdUserInfoProjector`;
- `OpenIdProviderMetadata`.

The exact `openid` scope activates OIDC behavior. The supported profile covers nonce, prompt, `max_age`/`auth_time`, ACR/AMR context, signed ID Tokens, subject identifiers, `at_hash`, `c_hash`, optional `s_hash` where explicitly bound, UserInfo projection and Discovery metadata.

Encrypted ID Tokens are not part of the required Epicrypt 3.0 provider API. General JWE remains available, but the provider does not advertise encrypted-ID-token interoperability in this release.

Implicit/hybrid flows, dynamic client registration, OIDC session/logout protocols, Request Objects, PAR, JAR and JARM are not advertised by the 3.0 provider core.

## Personal/API token surface

The final generic personal/API-token surface includes:

- `Auth\Personal\PersonalAccessTokenManager`;
- `PersonalAccessTokenPolicy`;
- `PersonalAccessTokenAbilities`;
- `PersonalAccessTokenWildcardPolicy`;
- `PersonalAccessTokenIssue`;
- `PersonalAccessTokenValidationResult` / `PersonalAccessTokenValidationStatus`;
- `PersonalAccessTokenRecord` / `PersonalAccessTokenStoreInterface`;
- optional `PersonalAccessTokenUsageStoreInterface`.

The profile uses purpose-isolated `pat+jwt` credentials plus authoritative metadata/state. Raw PAT JWT values are returned only when issued and are never persisted. Ability checks are exact unless an explicit wildcard policy enables wildcard semantics. `revokeAll()` and concurrent token issue for one subject require a deterministic serialization point in the production adapter.

## Store and adapter rule

Epicrypt ships framework-neutral public store interfaces and test-only in-memory/conformance adapters. Production applications must implement authoritative persistence using their own database/cache/transaction infrastructure.

The following state families require atomic/shared semantics across all accepting workers where selected:

- authorization-code one-time consume;
- refresh rotation/reuse/family and authorization revocation;
- OAuth client runtime lookup and security-sensitive enablement state;
- approved authorization state;
- optional access-token status state;
- JWT/client-assertion/DPoP replay state;
- PAT active/revoked state and issue-vs-revoke-all serialization.

An application adapter may be convenient, but it may not weaken these contracts through find-then-delete races, stale active caches, case folding of exact identifiers, or persistence of raw credentials.

## Framework/application ownership

The following remain outside Epicrypt 3.0:

- HTTP route registration and request/response serialization;
- TLS termination and network deployment;
- end-user login/account-selection UI;
- consent UI, application authorization decision and consent-history storage;
- account/principal repositories;
- concrete DB/cache implementations and backend transaction/locking mechanics;
- sessions/cookies;
- application permission policy and tenant/client administration outside protocol registration fields;
- rate limiting, audit and telemetry policy;
- environment/config/file loading and deployment key locations;
- OTP/WebAuthn domain mechanics owned by their specialist package.

## Persisted-format compatibility

Source/API changes in the major release do **not** retire established durable Epicrypt 2.x formats. The following remain readable/verifiable where already frozen as persisted contracts:

- `ep2` authenticated string/envelope payloads;
- `ep2` protected-file framing using XChaCha20-Poly1305 SecretStream;
- signed-payload v2 fixtures.

Applications should not bulk-reencrypt durable data merely because the package major changed. Explicit key lifecycle or application migration policy determines when a value is renewed.

OAuth authorization-code/refresh artifacts and the new auth-state APIs were introduced/finalized during Epicrypt 3 development; intermediate pre-release Epicrypt 3 formats/APIs receive no compatibility shim.

## Security and release contract

The 3.0 public surface is release-ready only when its exact release commit passes the ordinary PHP 8.4/8.5 stable/lowest QA and analyzer matrix, dependency/security audit, clean production installation, independent JOSE interoperability, independent OAuth/OIDC interoperability, positive AEGIS runtime validation, all security-critical mutation shards, parser/negative vectors, authentication performance/persistent-runtime memory evidence, and final documentation/API inventory checks.

No skipped security/completeness tests, analyzer suppression used to hide a defect, mutation exclusion, lowered threshold, or release-only compatibility workaround is part of this contract.
