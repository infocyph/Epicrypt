# Epicrypt 3.0 Public API Inventory

Baseline: `f80092978328cccaef0d2233b08ce95b453dd90a` (Epicrypt 2.1 current main when the 3.0 plan was opened).

This inventory exists to prevent accidental source/API breakage while the 3.0 major is implemented. API compatibility is not a release constraint, but every intentional removal or rename must be recorded here before it lands. Persisted-format compatibility is tracked separately and remains a hard release concern.

## Phase A/B decisions

| Surface | 3.0 decision | Notes |
| --- | --- | --- |
| `Crypto\SecretStream::encrypt()` / `decrypt()` | Keep | Local-path convenience wrappers remain. New stream-native methods become the core implementation. |
| `DataProtection\FileProtector` local-path methods | Keep | Local-path wrappers remain atomic and preserve the destination on failure. |
| `Integrity\FileHasher::hash()` / `verify()` | Keep | Path methods remain; stream-native methods are added underneath. |
| Pathwise types in Epicrypt production API | Remove dependency, no public replacement type | Epicrypt exposes PHP streams rather than `StorageContext`, Flysystem, Pathwise paths, or Pathwise registries. |
| `DataProtection\ProtectionResult` | Keep | Path/value-oriented result remains. Stream operations return the new metadata-only `ProtectionMetadata`. |
| `DataProtection\ProtectionMetadata` | Add | Represents protection metadata without inventing a fake output path/value for stream operations. |
| phpseclib 3 types/namespaces used internally | Replace in Phase C | Epicrypt 3 will be native phpseclib 4; no dual-major compatibility layer. |

## Confirmed 3.0 removals/renames

No additional public PHP symbol removal is confirmed during Phase A/B. Later phases may intentionally break API, but those changes must update this inventory before implementation.

## Later-phase API decisions that are still open

The following are review points, not approved removals yet:

- whether Argon2i remains selectable for new password hashes or becomes legacy-verification-only;
- whether backend-specific certificate classes under `Certificate\OpenSSL` remain public, move behind backend-neutral facades, or become explicitly low-level APIs;
- whether `Pkcs12` keeps its name or gains a backend-neutral PFX-facing API while preserving PKCS#12 interoperability;
- whether key-ring/key-rotation helpers consolidate into stronger key-set/readiness services;
- whether dedicated purpose-token convenience classes remain after the generic timed/purpose-token engine is completed;
- whether any phpseclib implementation types currently visible in signatures require replacement with Epicrypt-owned value objects.

## Update rule

Before any public symbol is removed, renamed, has a parameter/return contract changed, or begins throwing materially different public exceptions:

1. record the old symbol/contract here;
2. record the replacement or explicit removal rationale;
3. add/update migration notes and focused tests;
4. distinguish source/API breakage from persisted-format compatibility.
