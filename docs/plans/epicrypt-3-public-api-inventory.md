# Epicrypt 3.0 Public API Inventory

Baseline: `f80092978328cccaef0d2233b08ce95b453dd90a` (Epicrypt 2.1 current main when the 3.0 plan was opened).

Epicrypt 3.0 is unreleased. **Source/API compatibility is not a constraint while the 3.0 public surface is being finalized.** Superseded development APIs should be removed rather than retained behind aliases or parallel implementations. Persisted cryptographic formats are tracked separately and remain compatible where explicitly frozen by fixtures.

## Core/runtime decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `Crypto\SecretStream::encrypt()` / `decrypt()` | Keep | Local-path convenience wrappers remain; stream-native methods are the core implementation. |
| `DataProtection\FileProtector` local-path methods | Keep | Wrappers remain atomic and preserve destination on failure. |
| `Integrity\FileHasher::hash()` / `verify()` | Keep | Path methods remain; stream-native methods exist underneath. |
| Pathwise types in production API | Remove dependency | Epicrypt exposes PHP streams, not Pathwise/Flysystem types or registries. |
| `DataProtection\ProtectionResult` | Keep | Value-oriented result remains. |
| `DataProtection\ProtectionMetadata` | Add | Metadata-only result for stream operations. |

## PKI decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| phpseclib 3 implementation namespaces | Replace | Epicrypt 3 is native phpseclib `^4.0.1`; no dual-major shim. |
| phpseclib implementation objects in public contracts | Do not expose | Public APIs use PHP/native/Epicrypt values only. |
| `Certificate\OpenSSL` issuance helpers | Keep | Explicit accelerated low-level issuance APIs. |
| `Certificate\CertificateInspector` / `CsrInspector` | Add | Backend-neutral bounded inspection. |
| `Certificate\CertificateChainVerifier` | Add | Explicit trust/intermediate/purpose verification. |
| `Certificate\Pkcs12` | Keep | Public PFX/PKCS#12 boundary. |
| first-class CRL verification | Do not add in 3.0 | Requires a cleaner explicit-state model. |
| CMS API | Do not add in 3.0 | No concrete 3.0 consumer justifies the extra surface. |

## Application-crypto decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `Generate\KeyMaterial\KeyMaterialGenerator` boolean encoding parameters | Replace | Use `KeyMaterialEncoding`. |
| `KeyMaterialGenerator::forTokenSecret()` | Add | Canonical cryptographic application/token secret generator. |
| `Password\Secret\MasterSecretGenerator` | Remove | Use `KeyMaterialGenerator::forMasterSecret()`. |
| `Generate\KeyMaterial\TokenMaterialGenerator` | Remove | Use `RandomBytesGenerator::string()` or `forTokenSecret()`. |
| `Security\KeyPurpose::SIGNED_URL` | Add | Dedicated signed-URL key domain. |
| `Security\SignedUrl` raw-secret constructor | Keep | KeyRing mode supplements the simple single-key API. |
| `Security\AsymmetricSigningKeySet` | Add | Generic signing-key readiness/JWKS coherence. |
| `Token\Payload\PurposeToken` | Add | Generic purpose-bound timed signed-token mechanics. |
| domain-specific account-token helpers | Keep | Mandatory domain claims remain above generic mechanics. |

## Authentication protocol decisions

| Surface | 3.0 decision | Evidence / notes |
| --- | --- | --- |
| `Auth\Token\AuthTokenClass` | Add | `2b9c18e7`; canonical OAuth/OIDC/PAT token classes and JOSE types. |
| auth-token cross-substitution policy | Add | `2b9c18e7`; token type is verifier-bound. |
| auth-specific `Security\KeyPurpose` values | Add | `0b0a9d7b`; access/code/refresh/ID-token/PAT domains are separate. |
| `JwtPolicy` auth key-purpose binding | Add | `0b0a9d7b`; OAuth/OIDC verification no longer silently uses generic JWT signing keys. |
| RFC 9068 access-token profile | Keep/harden | Existing profile audited; auth class/key-domain hardening in `2b9c18e7` and `0b0a9d7b`. |
| `Auth\OAuth\AuthorizationCode` / artifact / issue | Add | `400497b3`; compact JWE, bounded claims, PKCE/client/redirect binding. |
| `Auth\OAuth\RefreshTokenArtifact*` | Add | `c1b30119`; confidentiality-preserving refresh JWE. |
| `Auth\OAuth\RefreshTokenGrant` | Add/finalize | `168c7b3e`; OAuth-native immutable authorization state. |
| `Auth\OAuth\RefreshTokenRecord` | Add | `168c7b3e`; exact authoritative state represented by the refresh credential. |
| `Auth\OAuth\RefreshTokenStoreInterface` | Add | `168c7b3e`; atomic consume + exact replacement persistence + reuse/family revocation semantics. |
| `Auth\OAuth\RefreshTokenManager` | Add | `168c7b3e`; issue/rotate/revoke over JOSE artifact + authoritative store. |
| `Auth\OAuth\RefreshTokenRotationResult/Status` | Add | `168c7b3e`; stable internal lifecycle outcomes. |
| `Token\Opaque\RefreshToken*` | Remove before 3.0 | `168c7b3e`; superseded development surface, no compatibility shim. |
| `Token\Opaque\OpaqueToken` | Keep | Generic random/opaque token primitive independent of OAuth refresh semantics. |
| test-only refresh in-memory/conformance store | Add | `168c7b3e`; reusable adapter contract checks. |

### Refresh persistence position

The final 3.0 refresh contract does **not** store the raw JWE and does not require a digest of the raw credential. The authenticated JWE exposes a cryptographically bound token ID (`jti`), family ID and authorization state; the store persists the exact authoritative record and atomically consumes/replaces it. Consumed history is retained through the authorization lifetime so ancestor reuse can revoke the family.

A successfully decrypted refresh JWE is not proof that the token is active. Cryptography authenticates the credential; `RefreshTokenStoreInterface` is authoritative for current/consumed/revoked state.

## Password/runtime decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `PasswordHashAlgorithm::ARGON2I` | Remove for new writes | Existing hashes remain verifiable and migrate after successful verification. |
| `PasswordHashAlgorithm::ARGON2ID` | Keep/default | Sole modern new-write profile. |
| `PasswordHashAlgorithm::BCRYPT` | Keep explicit compatibility | Opt-in; rejects passwords beyond bcrypt's safe bound. |
| compact protected-value size | Bound | String plaintext 16 MiB, encoded `ep2` 24 MiB, protected header 32 KiB, envelope plaintext 8 MiB. |

## Confirmed 3.0 removals/renames

- `Password\Secret\MasterSecretGenerator` → `Generate\KeyMaterial\KeyMaterialGenerator::forMasterSecret()`.
- `Generate\KeyMaterial\TokenMaterialGenerator` → `Generate\RandomBytesGenerator::string()` or `KeyMaterialGenerator::forTokenSecret()`.
- `KeyMaterialGenerator` boolean output switches → `KeyMaterialEncoding`.
- `PasswordHashAlgorithm::ARGON2I` → no new-write selector; stored Argon2i remains verification/rehash compatible.
- internal phpseclib 3 namespaces → phpseclib 4.0.1+.
- refresh-specific `Token\Opaque\RefreshTokenGrant`, `RefreshTokenManager`, `RefreshTokenRecord`, `RefreshTokenRotationResult`, `RefreshTokenRotationStatus`, `RefreshTokenStoreInterface` → final OAuth JOSE lifecycle under `Auth\OAuth`.

## Persisted-format position

The removals above are source/API changes. They do **not** retire or alter frozen Epicrypt 2.x `ep2` string/file formats or signed-payload v2 compatibility fixtures.

Epicrypt 3 does not create a package-version-driven `v3` wire format. Durable cryptographic formats have their own lifecycle. A future persisted-format retirement requires a concrete security/interoperability reason, frozen old/new fixtures, explicit read/write policy and documented migration path.

The new OAuth authorization-code and refresh-token JOSE formats are part of the unreleased 3.0 auth work; no legacy Epicrypt 3 auth-wire compatibility layer is required before the first 3.0 release.

## Update rule during 3.0 development

For every public auth/core batch:

1. record added/removed/renamed public symbols here;
2. prefer the clean final 3.0 API over compatibility shims;
3. update focused tests and plan checkboxes with the implementing commit;
4. distinguish source/API changes from persisted-format compatibility;
5. freeze this inventory only when the final 3.0 release candidate surface is intentionally stable.
