# Epicrypt 3.0 Public API Inventory

Baseline: `f80092978328cccaef0d2233b08ce95b453dd90a` (Epicrypt 2.1 main when the 3.0 plan opened).

Epicrypt 3.0 is unreleased. **Source/API compatibility is not a constraint while the final 3.0 surface is being built.** Superseded development APIs are removed instead of retained behind aliases/parallel implementations. Persisted cryptographic formats are tracked separately and remain compatible where explicitly frozen by fixtures.

## Core/runtime decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `Crypto\SecretStream` path wrappers | Keep | Stream-native methods are core; local-path convenience remains. |
| `DataProtection\FileProtector` path methods | Keep | Atomic local-path wrappers remain. |
| `Integrity\FileHasher` path methods | Keep | Stream-native core underneath. |
| Pathwise types in production API | Remove dependency | Epicrypt exposes PHP streams, not Pathwise/Flysystem types. |
| `DataProtection\ProtectionMetadata` | Add | Metadata-only stream result. |
| phpseclib 3 namespaces | Replace | Native phpseclib `^4.0.1`; no dual-major shim. |
| phpseclib implementation objects in public contracts | Do not expose | Public APIs use native/Epicrypt values. |
| `Certificate\CertificateInspector` / `CsrInspector` | Add | Bounded backend-neutral inspection. |
| `Certificate\CertificateChainVerifier` | Add | Explicit trust/purpose verification. |
| first-class CRL/CMS API | Do not add in 3.0 | No clean/current consumer justification. |
| `Password\Secret\MasterSecretGenerator` | Remove | Use `KeyMaterialGenerator::forMasterSecret()`. |
| `Generate\KeyMaterial\TokenMaterialGenerator` | Remove | Use `RandomBytesGenerator::string()` / `forTokenSecret()`. |
| `Security\KeyPurpose::SIGNED_URL` | Add | Dedicated signing domain. |
| `Security\AsymmetricSigningKeySet` | Add | Key readiness/JWKS coherence. |
| `Token\Payload\PurposeToken` | Add | Generic purpose-bound timed token mechanics. |

## Authentication protocol decisions

| Surface | 3.0 decision | Evidence / notes |
| --- | --- | --- |
| `Auth\Token\AuthTokenClass` + substitution policy | Add | `2b9c18e7`. |
| auth-specific `Security\KeyPurpose` + `JwtPolicy` binding | Add | `0b0a9d7b`. |
| RFC 9068 access-token profile | Keep/harden | baseline + `2b9c18e7`, `0b0a9d7b`. |
| `Auth\OAuth\AuthorizationCode*` artifact family | Add | `400497b3`; JWE + PKCE/client/redirect/OIDC transaction binding. |
| `Auth\OAuth\RefreshTokenArtifact*` | Add | `c1b30119`. |
| `Auth\OAuth\RefreshTokenGrant/Record/StoreInterface/Manager/Result/Status` | Add/final | `168c7b3e`; authoritative JOSE refresh lifecycle. |
| `Token\Opaque\RefreshToken*` | Remove before 3.0 | `168c7b3e`; no compatibility shim. |
| `Token\Opaque\OpaqueToken` | Keep | Generic opaque/random-token primitive only. |
| `Auth\Internal\AuthProtocolPolicy` | Add internal substrate | `2b9c1c02`; shared hard OAuth/OIDC/PAT ceilings. |
| `Auth\OAuth\AuthorizationCodeRecord/ConsumeStatus/StoreInterface` | Add | `8326444e`; atomic exact-state one-time consume. |
| `Auth\OAuth\OAuthClientType/OAuthGrantType/OAuthClientAuthenticationMethod` | Add | `d2ff4c81`; typed registration profile. |
| `Auth\OAuth\OAuthClientSecret` | Add | `d2ff4c81`; one-way secret material only. |
| `Auth\OAuth\OAuthClientKeySet` | Add | `d2ff4c81`; bounded public-only assertion JWKS, explicit alg/kid. |
| `Auth\OAuth\OAuthClient` | Add | `d2ff4c81`; immutable protocol registration snapshot. |
| `Auth\OAuth\OAuthClientStoreInterface` | Add | `d2ff4c81`; exact case-sensitive read-only runtime lookup. |
| `Auth\OAuth\OAuthClientAssertion*` + `OAuthClientAuthenticator` | Add | `5c01d1bb`; RFC-7523-style strict `private_key_jwt`, bounded claims/signature/replay. |
| OAuth-specific replay-store duplicate | Do not add | `5c01d1bb`; reuse generic atomic `JwtReplayStoreInterface` for client assertions and DPoP. |
| `Auth\OAuth\OAuthAuthorizationRecord/StoreInterface` | Add | `143b1c21`; approved authorization state/revocation. |
| `Auth\OAuth\OAuthAccessTokenStatusRecord/StoreInterface` | Add | `143b1c21`; optional authoritative JWT `jti` status/revocation. |
| `Auth\Personal\PersonalAccessTokenRecord/StoreInterface` | Add | `143b1c21`; metadata-only PAT state/list/revoke/revoke-all. |
| Epicrypt consent-history store | Do not add | Consent history is application policy; Epicrypt persists approved authorization state only. |
| `Auth\OAuth\OAuthErrorCode/OAuthProtocolError` | Add | `ad14609c`; transport-neutral OAuth error + safe redirect target/state. |
| `Auth\OAuth\OAuthAuthorizationRequest/Result` | Add | `ad14609c`; validated authorization request/result DTOs. |
| `Auth\OAuth\OAuthAuthorizationRequestValidator` | Add | `ad14609c`; bounded duplicate-aware parameter input, exact redirect, code-only, S256 PKCE, grant/scope checks. |
| `Auth\OAuth\OAuthEndpointCapability/OAuthEndpointCapabilityCatalog` | Add | `ad14609c`; explicit capabilities only, no route registration. |
| auth in-memory/conformance stores | Test-only | `168c7b3e`, `8326444e`, `d2ff4c81`, `143b1c21`. |

### Authorization-request input boundary

The authorization validator accepts a transport-neutral parameter map where a scalar represents one occurrence and a list preserves repeated occurrences. Singleton OAuth parameters represented as repeated values are rejected. This prevents framework parsers from silently deciding duplicate semantics for security-critical authorization parameters.

A redirect becomes eligible for protocol-error redirection only after exact registration validation (or selection of the sole registered redirect when the request omits `redirect_uri`). Unknown/disabled clients and redirect mismatches never produce a redirect target in the result.

### Authorization-code persistence position

Raw authorization-code JWE is never persisted. Persistence uses authenticated `jti` plus exact canonical state. Successful cryptographic decryption does not provide one-time semantics; `AuthorizationCodeStoreInterface` is authoritative for consume/replay state.

### Refresh persistence position

Raw refresh JWE is never persisted and no digest of the raw JWE is required. The authenticated credential exposes token ID/family/authorization state; the store persists exact authoritative state and atomically consumes/replaces it. Decryption proves cryptographic validity, not active lifecycle state.

### Client credential position

Client runtime registration is immutable/read-only. Secret credentials are stored as one-way hashes. `private_key_jwt` trusts only explicitly registered public asymmetric keys: no embedded `jwk`, remote `jku`, or `x5*` locator can choose trust material. Assertions require bounded `iss/sub/aud/exp/iat/jti`, are algorithm/key pinned, and consume replay state through `JwtReplayStoreInterface` through `exp + leeway`.

### Authoritative state position

OAuth authorization, optional access-token status and PAT active/revoked state are security-sensitive authoritative reads. Adapters must not return stale active records after revocation/disablement commits. PAT raw JWTs are never persisted. `revokeAll()` and concurrent issue for one PAT subject require a deterministic serialization point.

## Confirmed 3.0 removals/renames

- `Password\Secret\MasterSecretGenerator` → `Generate\KeyMaterial\KeyMaterialGenerator::forMasterSecret()`.
- `Generate\KeyMaterial\TokenMaterialGenerator` → `Generate\RandomBytesGenerator::string()` or `KeyMaterialGenerator::forTokenSecret()`.
- boolean `KeyMaterialGenerator` output switches → `KeyMaterialEncoding`.
- `PasswordHashAlgorithm::ARGON2I` → no new-write selector; old hashes remain verification/rehash compatible.
- internal phpseclib 3 namespaces → phpseclib 4.0.1+.
- refresh-specific `Token\Opaque\RefreshToken*` → final `Auth\OAuth\RefreshToken*` JOSE lifecycle.

## Persisted-format position

Source/API changes do **not** retire frozen Epicrypt 2.x `ep2` string/file formats or signed-payload v2 fixtures. Durable cryptographic formats have their own lifecycle and require explicit migration evidence before retirement.

OAuth authorization-code/refresh JOSE and the new auth-state APIs are unreleased Epicrypt 3 surfaces; no compatibility layer for intermediate Epicrypt 3 development formats/APIs is required before the initial 3.0 release.

## Update rule during 3.0 development

After every public batch:

1. record added/removed/renamed public symbols here;
2. prefer the final 3.0 API over compatibility shims;
3. update focused tests and plan checkboxes with implementing commit;
4. distinguish source/API changes from persisted-format compatibility;
5. freeze this inventory only when the release-candidate public surface is intentionally stable.
