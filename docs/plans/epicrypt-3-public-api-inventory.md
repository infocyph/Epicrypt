# Epicrypt 3.0 Public API Inventory

Baseline: `f80092978328cccaef0d2233b08ce95b453dd90a` (Epicrypt 2.1 current main when the 3.0 plan opened).

Epicrypt 3.0 is unreleased. **Source/API compatibility is not a constraint while the final 3.0 surface is being built.** Superseded development APIs are removed rather than retained behind aliases or parallel implementations. Persisted cryptographic formats are tracked separately and remain compatible where explicitly frozen by fixtures.

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
| `Auth\Token\AuthTokenClass` | Add | `2b9c18e7`; canonical OAuth/OIDC/PAT token classes/types. |
| auth-token substitution policy | Add | `2b9c18e7`. |
| auth-specific `Security\KeyPurpose` values | Add | `0b0a9d7b`. |
| `JwtPolicy` auth key-purpose binding | Add | `0b0a9d7b`. |
| RFC 9068 access-token profile | Keep/harden | baseline + `2b9c18e7`, `0b0a9d7b`. |
| `Auth\OAuth\AuthorizationCode*` artifact family | Add | `400497b3`; JWE + PKCE/client/redirect/OIDC transaction binding. |
| `Auth\OAuth\RefreshTokenArtifact*` | Add | `c1b30119`. |
| `Auth\OAuth\RefreshTokenGrant/Record/StoreInterface/Manager/Result/Status` | Add/final | `168c7b3e`; authoritative JOSE refresh lifecycle. |
| `Token\Opaque\RefreshToken*` | Remove before 3.0 | `168c7b3e`; no compatibility shim. |
| `Token\Opaque\OpaqueToken` | Keep | Generic opaque/random-token primitive only. |
| `Auth\Internal\AuthProtocolPolicy` | Add internal substrate | `2b9c1c02`; shared hard OAuth/OIDC/PAT ceilings; future public policy may only tighten. |
| `Auth\OAuth\AuthorizationCodeRecord` | Add | `8326444e`; `jti` + authorization + expiry + canonical claim-state digest. |
| `Auth\OAuth\AuthorizationCodeConsumeStatus` | Add | `8326444e`; `CONSUMED/REPLAYED/EXPIRED/INVALID`. |
| `Auth\OAuth\AuthorizationCodeStoreInterface` | Add | `8326444e`; atomic exact-state one-time consume. |
| refresh/code in-memory + conformance stores | Test-only | `168c7b3e`, `8326444e`. |

### Authorization-code persistence position

Raw authorization-code JWE is never persisted. Persistence uses authenticated `jti` plus an exact canonical state fingerprint. Successful cryptographic decryption does not provide one-time semantics; `AuthorizationCodeStoreInterface` is authoritative for consume/replay state.

### Refresh persistence position

Raw refresh JWE is never persisted and no digest of the raw JWE is required. The authenticated credential exposes token ID/family/authorization state; the store persists the exact authoritative record and atomically consumes/replaces it. Decryption proves cryptographic validity, not active lifecycle state.

## Confirmed 3.0 removals/renames

- `Password\Secret\MasterSecretGenerator` → `Generate\KeyMaterial\KeyMaterialGenerator::forMasterSecret()`.
- `Generate\KeyMaterial\TokenMaterialGenerator` → `Generate\RandomBytesGenerator::string()` or `KeyMaterialGenerator::forTokenSecret()`.
- boolean `KeyMaterialGenerator` output switches → `KeyMaterialEncoding`.
- `PasswordHashAlgorithm::ARGON2I` → no new-write selector; old hashes remain verification/rehash compatible.
- internal phpseclib 3 namespaces → phpseclib 4.0.1+.
- refresh-specific `Token\Opaque\RefreshToken*` → final `Auth\OAuth\RefreshToken*` JOSE lifecycle.

## Persisted-format position

Source/API changes do **not** retire frozen Epicrypt 2.x `ep2` string/file formats or signed-payload v2 fixtures. Durable cryptographic formats have their own lifecycle and require explicit migration evidence before retirement.

New OAuth authorization-code and refresh JOSE formats are unreleased Epicrypt 3 auth formats; no compatibility layer for intermediate Epicrypt 3 development formats is required before the initial 3.0 release.

## Update rule during 3.0 development

After every public batch:

1. record added/removed/renamed public symbols here;
2. prefer the final 3.0 API over compatibility shims;
3. update focused tests and plan checkboxes with implementing commit;
4. distinguish source/API changes from persisted-format compatibility;
5. freeze this inventory only when the release-candidate public surface is intentionally stable.
