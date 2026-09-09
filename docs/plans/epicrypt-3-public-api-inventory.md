# Epicrypt 3.0 Public API Inventory

Baseline: `f80092978328cccaef0d2233b08ce95b453dd90a` (Epicrypt 2.1 current main when the 3.0 plan was opened).

This inventory records intentional 3.0 source/API changes. API compatibility is not a release constraint for the major, but persisted cryptographic compatibility is tracked separately and remains a hard release concern.

## Phase A/B decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `Crypto\SecretStream::encrypt()` / `decrypt()` | Keep | Local-path convenience wrappers remain. Stream-native methods are the core implementation. |
| `DataProtection\FileProtector` local-path methods | Keep | Local-path wrappers remain atomic and preserve the destination on failure. |
| `Integrity\FileHasher::hash()` / `verify()` | Keep | Path methods remain; stream-native methods are added underneath. |
| Pathwise types in Epicrypt production API | Remove dependency, no public replacement type | Epicrypt exposes PHP streams rather than `StorageContext`, Flysystem, Pathwise paths, or Pathwise registries. |
| `DataProtection\ProtectionResult` | Keep | Value-oriented result remains. Stream operations return metadata-only `ProtectionMetadata`. |
| `DataProtection\ProtectionMetadata` | Add | Represents protection metadata without inventing a fake output path/value for stream operations. |

## Phase C / PKI decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| phpseclib 3 implementation namespaces | Replace | Epicrypt 3 is native phpseclib `^4.0.1`; no dual-major shim or runtime namespace probing. |
| phpseclib implementation objects in public contracts | Do not expose | Public Epicrypt APIs use strings, arrays, enums, Epicrypt result objects and Epicrypt exceptions. |
| `Certificate\OpenSSL` issuance helpers | Keep | They remain explicit low-level/accelerated issuance APIs; OpenSSL is still a required backend. |
| `Certificate\CertificateInspector` / `CsrInspector` | Add | Backend-neutral bounded inspection through phpseclib 4. |
| `Certificate\CertificateChainVerifier` | Add | Explicit trust-anchor/intermediate/purpose verification with no global trust registry or hidden fetching. |
| `Certificate\Pkcs12` | Keep name and public role | Public PFX/PKCS#12 boundary. phpseclib 4 handles bounded parsing/model validation; OpenSSL serializes interoperable containers. |
| first-class CRL verification | Do not add in 3.0 | Available convenience validation depends on shared/global issuer state; explicit-state design is required before a future API. |
| CMS API | Do not add in 3.0 | No concrete current consumer justifies the parser/interoperability/misuse surface. |

## Phase D / application-crypto decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `Generate\KeyMaterial\KeyMaterialGenerator` boolean encoding parameters | Replace | Use `KeyMaterialEncoding::BASE64URL`, `RAW`, or `HEX`; requested lengths always mean raw entropy bytes before encoding. |
| `Generate\KeyMaterial\KeyMaterialGenerator::forTokenSecret()` | Add | Canonical 32-byte cryptographic application/token signing or MAC secret generator with explicit encoding. |
| `Password\Secret\MasterSecretGenerator` | Remove | Duplicated entropy/Base64URL generation. Use `KeyMaterialGenerator::forMasterSecret()`. Persisted wrapped-secret formats are unchanged. |
| `Generate\KeyMaterial\TokenMaterialGenerator` | Remove | Thin duplicate wrapper. Use `RandomBytesGenerator::string()` for generic opaque/random token material, or `KeyMaterialGenerator::forTokenSecret()` for a cryptographic secret. |
| `Security\KeyPurpose::SIGNED_URL` | Add | Signed URLs use a dedicated key domain rather than generic signed-payload keys. |
| `Security\SignedUrl` raw-secret constructor | Keep | Existing raw-secret signed-URL wire format remains supported; KeyRing mode adds authenticated key selection/rotation. |
| `Security\AsymmetricSigningKeySet` | Add | Owns generic asymmetric signing-key readiness, key-pair coherence, eligibility, and validated public JWKS export. |
| `Token\Payload\PurposeToken` | Add | Owns generic purpose-bound timed signed-token mechanics and KeyRing-aware verification. |
| domain-specific account token helpers | Keep | Password-reset/email-verification/remember/action helpers retain mandatory domain claims while generic timed mechanics live underneath. |

## Phase G password/runtime decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `PasswordHashAlgorithm::ARGON2I` | Remove for new writes | Existing Argon2i hashes remain verifiable via `password_verify()` and are rehashed to configured Argon2id after successful verification. |
| `PasswordHashAlgorithm::ARGON2ID` | Keep/default | Sole modern new-write password profile. |
| `PasswordHashAlgorithm::BCRYPT` | Keep explicit compatibility | Bcrypt remains opt-in and rejects passwords longer than 72 bytes. |
| compact protected-value size | Bound | String plaintext 16 MiB, encoded `ep2` 24 MiB, protected header 32 KiB; envelope plaintext 8 MiB. Larger data belongs on `FileProtector` streams. |

## Confirmed 3.0 removals/renames

- `Password\Secret\MasterSecretGenerator` -> `Generate\KeyMaterial\KeyMaterialGenerator::forMasterSecret()`.
- `Generate\KeyMaterial\TokenMaterialGenerator` -> `Generate\RandomBytesGenerator::string()` for random token text, or `KeyMaterialGenerator::forTokenSecret()` for signing/MAC secrets.
- `KeyMaterialGenerator` boolean output switches -> `KeyMaterialEncoding`.
- `PasswordHashAlgorithm::ARGON2I` -> no new-write selector; stored Argon2i hashes remain verification/rehash compatible.
- internal phpseclib 3 namespaces -> phpseclib 4.0.1+.

These are source/API changes only. They do **not** retire or alter the frozen Epicrypt 2.x `ep2` string/file formats or signed-payload v2 compatibility fixtures.

## Final persisted-format position

Epicrypt 3 does not create a package-version-driven `v3` wire format. New package APIs may change while durable cryptographic formats keep their own version lifecycle. A future wire-format retirement requires a concrete security/interoperability reason, frozen old/new fixtures, explicit read/write policy, and a documented migration path.

## Update rule

Before any future public symbol is removed, renamed, has a parameter/return contract changed, or begins throwing materially different public exceptions:

1. record the old symbol/contract here;
2. record the replacement or explicit removal rationale;
3. add/update migration notes and focused tests;
4. distinguish source/API breakage from persisted-format compatibility.
