# Epicrypt 3.0 — Final Development Plan

## Status

Target release: **Epicrypt 3.0**

Planning branch: `epicrypt-3/architecture-plan`

Baseline audited from current `main` at `f80092978328cccaef0d2233b08ce95b453dd90a`.

Implementation status: **Phase A + Phase B + Phase C complete; Phase D in progress with Batches 1–5 complete**.

Latest verified implementation batch: **Phase D Batch 5** — `93f8e8a0307782b09b394b408e8bb6e3be75dd7f`.

### Progress ledger

#### 2026-09-08 — Phase A+B

Completed:

- froze durable Epicrypt 2.x protected-file, string-protection and signed-payload compatibility fixtures;
- moved `SecretStream`, `FileProtector` and `FileHasher` to native caller-owned PHP stream cores while retaining local-path convenience APIs;
- removed all production Pathwise imports and removed Pathwise from Composer `require`;
- moved Pathwise to `require-dev ^4.0` solely for explicit interoperability tests;
- added bounded short-read/short-write handling, shared input locking and atomic local output publication;
- added `ProtectionMetadata`, the public API inventory, Pathwise 4 explicit-context isolation tests and a production-only no-Pathwise smoke/gate;
- captured comparable Epicrypt 2.1/current-branch benchmark evidence and attributed stream/local-wrapper overhead.

Validation:

- no-Pathwise production install gate: green;
- Pathwise 4 explicit-context interoperability: green;
- baseline/performance evidence job: green;
- full PHPForge/security matrix subsequently remained green through Phase D Batch 5.

#### 2026-09-08 — Phase C

Closed at `d1bf66b2e3a9882a6f7bf8581586b833c0aeb362`.

- migrated natively to phpseclib `^4.0.1` with no phpseclib-3 compatibility shim;
- migrated JWS/JWT RSA-PSS, JWE RSA-OAEP-256, BigInteger/JWKS and password-protected private-JWK paths;
- normalized phpseclib 4 exception/error handling and prevented backend key/passphrase details from becoming public Epicrypt errors;
- added migration-specific regression and independent JOSE interoperability coverage;
- superseded Dependabot PR #29.

Validation:

- Epicrypt 3 Phase A+B Gates #29 (`34255686357`): green;
- Security & Standards #77 (`34255687254`): green.

#### 2026-09-09 — Phase D Batch 1

Closed at `8eb1d07e7beafc3dc7f1f88a9ad8b86e62b6eb3a`.

- added generic purpose-bound timed tokens with typed verification results;
- added exact active/fallback `KeyRing` issuance/verification and public-safe key metadata;
- added labelled/domain-separated application HKDF derivation;
- added Foundation-equivalent simple-token fixtures and adversarial/rotation tests.

Validation: A+B #54 and Security #102 green.

#### 2026-09-09 — Phase D Batch 2

Closed at `8edb0be9290a5c06174f4c4cc294008c48ddde68`.

- added `AsymmetricSigningKeySet` as the generic signing-key readiness boundary;
- validates active/fallback eligibility, key id, purpose, issuer, algorithm and private/public key coherence centrally;
- exports public-only JWKS and typed readiness failures without backend leakage;
- covers RSA/PKCS#1, RSA-PSS, EC and Ed25519/EdDSA, including encrypted private keys.

Validation: A+B #61 and Security #109 green.

#### 2026-09-09 — Phase D Batch 3

Closed at `fff714e1acfa127dfd5b7ddb2d960791eaf8204f`.

- added dedicated `KeyPurpose::SIGNED_URL` isolation;
- added `KeyRing` signed-URL rotation with authenticated `ep_kid` selection;
- retained the raw-secret v2 wire format;
- reports matched/fallback key metadata without exposing secret material;
- added rotation, tampering, unknown/missing-kid, cross-purpose and frozen-format tests.

Validation: A+B #67 and Security #115 green.

#### 2026-09-09 — Phase D Batch 4

Closed at `fc398e004e664e088df8a2ab57c2c726b3606374`.

- added explicit raw/Base64URL/hex `KeyMaterialEncoding`;
- made `KeyMaterialGenerator` the canonical application/master/token-secret generation boundary;
- added `forTokenSecret()` with 32 raw entropy bytes and Foundation-compatible 64-character lowercase hex output;
- removed duplicate password-domain `MasterSecretGenerator`;
- added entropy/encoding tests and mutation coverage.

Validation: A+B #78 and Security #126 green.

#### 2026-09-09 — Phase D Batch 5

Closed implementation head: `93f8e8a0307782b09b394b408e8bb6e3be75dd7f`.

- proved `FileProtector` local-path operations are already the single required crypto-adjacent publication layer;
- added tests proving `0600` local outputs, preservation of existing destinations after failed protect/unprotect operations, and cleanup of sibling staging artifacts;
- corrected data-protection documentation so Epicrypt owns local atomic crypto publication, stream callers own publication/rollback, and application/storage layers retain symlink/path policy;
- intentionally added no second public staging abstraction.

Validation: A+B #80 (`34303163908`) and Security #128 (`34303164238`) green.

This is a **major release**. Source/API backward compatibility is not a release constraint. **Persisted cryptographic compatibility is a separate release constraint and must not be broken casually.** Existing durable encrypted/signed material must remain readable/verifiable unless a concrete security reason requires retirement and a migration path is supplied.

---

## 1. Final ownership model

### Epicrypt owns

- cryptographic primitives and safe cryptographic composition;
- secret/key generation and deterministic key derivation;
- key identifiers, key rings, key eligibility, rotation and verification readiness;
- versioned/signed/encrypted payload formats;
- generic purpose-bound timed tokens;
- password hashing/verification/rehash/generation/policy helpers;
- JWT/JWS/JWE/JWK/JWKS, DPoP and OpenID cryptographic validation;
- opaque-token material and generic refresh-token rotation mechanics;
- certificate/key/CSR/chain/PFX/CMS/PKI cryptographic operations;
- local/stream data-protection transforms and framing/authentication rules;
- generic integrity hashing/MAC/signature operations;
- strict cryptographic limits, algorithm policy and safe result/exception types.

### Pathwise owns

- storage configuration/contexts and filesystem adapters;
- path routing, filesystem schemes and storage identity;
- localization/staging/commit mechanics for storage adapters;
- safe generic filesystem reading/writing;
- uploads/downloads/archive/sync/retention/storage policy.

Epicrypt must not own a storage registry or rely on Pathwise global mounts.

### OTP owns

- OTP algorithms/provisioning;
- TOTP/HOTP/AOTP behavior;
- replay/claim/consume semantics for OTP;
- OTP-specific recovery-code behavior;
- passkey/WebAuthn ceremonies and MFA orchestration;
- OTP-specific persistence/cache contracts.

Epicrypt **must not depend on OTP** in production.

### Foundation owns

- application configuration/environment selection;
- DI/provider graph and runtime lifecycle;
- application paths/CLI;
- HTTP/router/session/auth/application OAuth orchestration;
- account/user/authorization behavior;
- database/cache repositories and transactions;
- application audit policy/diagnostics;
- selecting/configuring Epicrypt, OTP and Pathwise;
- adapting lower-layer results into application/HTTP contracts.

### Target dependency direction

```text
Foundation
  ├── Epicrypt 3
  ├── OTP 6.x
  └── Pathwise 4

Epicrypt 3
  └── phpseclib 4

OTP 6.x
  └── no Epicrypt or Pathwise production dependency required

Pathwise 4
  └── no Epicrypt or OTP dependency
```

Do not solve Foundation compatibility with aliases/replaces or a Pathwise 3 compatibility layer.

---

## 2. Composer/dependency reset

### 2.1 Pathwise

- [x] remove `infocyph/pathwise` from production `require`;
- [x] add `infocyph/pathwise: ^4.0` to `require-dev` only for interoperability tests;
- [x] do not expose/depend on Pathwise static/global mount APIs;
- [x] make file crypto stream-first;
- [x] retain local path convenience wrappers over Epicrypt-owned stream/local helpers;
- [x] prove Pathwise 4 `StorageContext` streams feed Epicrypt without ambient state;
- [x] avoid a Pathwise `suggest` entry unless a real optional public integration class is shipped.

### 2.2 OTP

- [x] do not add OTP to Epicrypt `require` or `require-dev` merely for Foundation integration;
- [x] keep generic cryptographic facilities in Epicrypt and MFA semantics in OTP;
- [x] document that Foundation composes the packages rather than the packages depending on each other;
- [ ] if OTP later needs deterministic subkeys, keep the dependency direction optional/application-supplied rather than making Epicrypt mandatory.

### 2.3 phpseclib

- [x] require `phpseclib/phpseclib ^4.0.1`;
- [x] migrate from `phpseclib3\...` to `phpseclib4\...`;
- [x] do not ship a dual phpseclib 3/4 compatibility layer;
- [x] supersede/close Dependabot PR #29;
- [x] audit phpseclib calls for v4 exception semantics;
- [x] handle password-protected key loading with v4-safe failure handling;
- [x] revalidate RSA-PSS behavior and salt-length handling;
- [x] migrate `BigInteger`, `PublicKeyLoader`, RSA/private/public key and JOSE internals to v4;
- [x] add phpseclib-4-specific regression/interoperability tests.

### 2.4 extensions and PSR packages

- [x] retain PHP `^8.4` as the floor;
- [x] test PHP 8.4 and 8.5;
- [ ] review whether `ext-openssl` remains mandatory after the certificate pass;
- [x] retain `ext-sodium` for modern primitives/AEGIS capability;
- [ ] retain only PSR clock/HTTP/cache contracts required by public capabilities after later subsystem cleanup;
- [x] no framework-specific dependency.

---

## 3. Stream-first file/data protection and Pathwise decoupling

```text
path/file/storage owner
        ↓
PHP stream/resource
        ↓
Epicrypt stream crypto/integrity engine
        ↓
PHP stream/resource
        ↓
caller/storage owner commits destination
```

### Required changes

- [x] stream-native `SecretStream` encrypt/decrypt;
- [x] stream-native `FileProtector` protection/unprotection;
- [x] stream-native `FileHasher` hashing/verification;
- [x] bounded chunking and strict framing;
- [x] stream capability validation with Epicrypt exceptions;
- [x] cleanup/zeroization of internal state where practical;
- [x] no retained stream references after an operation;
- [x] local path wrappers over stream operations;
- [x] existing local destinations preserved on crypto failure via sibling atomic staging/commit;
- [x] core local-path APIs reject storage/stream-wrapper schemes;
- [x] Pathwise 4 independent-context integration tests;
- [x] benchmark stream core and local wrapper overhead separately;
- [ ] add a true remote-adapter stream fixture if later storage integration requires one beyond the current explicit-stream proof.

### File format compatibility

- [x] continue reading Epicrypt 2.x protected-file framing;
- [x] remove package-version-specific protected-file error text;
- [x] separate package version from wire/storage format version;
- [x] do not create a v3 wire format merely because the package is 3.0;
- [ ] if a new format is ever justified, ship read-old/read-new/write-new plus deterministic migration fixtures.

---

## 4. Foundation → Epicrypt ownership transfer

### 4.1 Remove Foundation `HmacTokenCodec`

- [x] provide an ergonomic purpose-bound signed payload/timed-token API with typed verification results;
- [x] support context/domain separation, `iat`, `exp`, token id, purpose and caller claims;
- [x] support active/fallback `KeyRing` verification and report the key used;
- [x] expose stable invalid/expired/not-yet-valid/wrong-purpose/wrong-context/unsupported-format/key-not-usable reasons without key leakage;
- [x] use Epicrypt token material generation for token IDs;
- [ ] Foundation should delete `HmacTokenCodec` after consumer migration.

### 4.2 Reduce Foundation simple timed-token implementations

- [x] move generic timed-token issue/verify mechanics into Epicrypt;
- [x] keep account/user/authentication orchestration outside Epicrypt;
- [ ] Foundation keeps claim mapping, repositories, revocation and application-contract adaptation;
- [ ] Foundation adapters become small claim/result translators after integration.

### 4.3 Key derivation

- [x] make `KeyDeriver` the canonical Epicrypt HKDF/domain-separated derivation boundary;
- [x] provide explicit labels/context/salt/output-length policy;
- [x] derive independent application subkeys without accidental cross-purpose reuse;
- [ ] Foundation should migrate generic application derivation to this boundary;
- [ ] OTP-specific recovery-code mechanics remain OTP-owned.

### 4.4 Environment secret generation

- [x] expose a clear Epicrypt master/application/token-secret generator with raw/Base64URL/hex material;
- [x] provide minimum entropy/length guidance and tests;
- [ ] Foundation should ask Epicrypt for the secret and only own `.env` editing/cache invalidation.

### 4.5 Environment-file protection

Target split:

- Foundation: app-relative paths, CLI flags, key locator, force/symlink policy, config-cache invalidation;
- Epicrypt: authenticated protect/unprotect, metadata, bounded streaming and one safe local atomic publication layer;
- storage caller: localization/remote commit semantics for stream APIs.

- [x] make Epicrypt local protected-file operations safe enough that Foundation does not need a second crypto staging protocol;
- [x] preserve existing destination after failed protect/unprotect operations;
- [x] publish local secret outputs with restrictive `0600` staging/output permissions where POSIX permissions apply;
- [x] keep application-specific symlink/path policy outside Epicrypt.

### 4.6 OAuth/JWT signing-key readiness

- [x] add a generic asymmetric signing-key-set/readiness boundary;
- [x] validate active private/public key match without a fake readiness JWT;
- [x] validate key id, algorithm, purpose, issuer and eligibility centrally;
- [x] expose public-only JWKS from the validated set;
- [x] expose typed non-sensitive readiness failures;
- [ ] Foundation remains responsible for reading configuration/files and readiness audit events;
- [ ] Foundation removes its duplicate crypto-only key-set semantics after integration.

### 4.7 What must not move from Foundation

Do not move OAuth routes/grants/consent, token-revocation persistence, user/device repositories, session/cookie/CSRF wiring, application rate limiting/audit policy, Foundation path/config/CLI behavior, WebAuthn/OTP domain behavior, or HTTP response handling into Epicrypt.

---

## 5. Key material, KeyRing and rotation redesign

- [x] separate public-safe metadata from secret key material in public results/JWKS-facing APIs;
- [ ] finish the library-wide `#[SensitiveParameter]` pass;
- [ ] centralize key-id grammar/limits across every subsystem;
- [ ] normalize algorithm identifiers across every subsystem;
- [x] preserve exact-one-active-write-key semantics;
- [x] preserve active/fallback read behavior explicitly;
- [ ] decide whether additional retired/revoked distinctions are needed beyond current `KeyStatus`;
- [ ] define/test all `not_before`/`not_after` exact boundaries library-wide;
- [ ] finish JWK `use`/`key_ops` validation pass;
- [x] add immutable/public-safe `KeyMetadata`;
- [x] add generic key-pair matching/readiness checks;
- [x] use RFC 7638 JWK thumbprints for canonical RSA/EC public identity where applicable;
- [x] avoid trying every key when a validated `kid` is available in migrated KeyRing paths;
- [x] add rotation vectors proving fallback reads and active-only writes;
- [ ] benchmark larger realistic key-ring sets.

### Key providers

- [ ] evaluate an infra-neutral `KeyProviderInterface`/`KeyResolverInterface` only if later KMS integration materially benefits;
- [ ] keep environment/file/Vault/AWS/GCP specifics outside core unless optional integrations are deliberately shipped;
- [x] never make Epicrypt responsible for application configuration discovery;
- [x] no implicit global key registry.

---

## 6. phpseclib 4 native migration

### Namespace/API migration

- [x] `phpseclib3` → `phpseclib4` namespaces;
- [x] audit `PublicKeyLoader` exceptions/password handling;
- [x] audit RSA PKCS#1/PSS signing/verification;
- [x] verify PSS behavior with independent interoperability coverage;
- [x] verify EC handling and DER↔JOSE conversion paths used by Epicrypt;
- [ ] separately review Curve25519/448 behavior in the later primitive/certificate pass where those backends are exposed;
- [x] migrate/audit BigInteger serialization/import/export paths;
- [x] replace v3 boolean/`false` assumptions with v4 exception handling where required;
- [x] collapse backend key/passphrase errors to stable non-sensitive Epicrypt failures;
- [x] record native-v4 benchmark/interoperability evidence.

### No dual-major compatibility layer

- [x] no runtime namespace probes for phpseclib 3/4;
- [x] no `class_alias` compatibility bridge;
- [x] no `^3 || ^4` production requirement;
- [ ] complete the final 2.x→3.0 migration guide before RC.

---

## 7. Certificate/PKI modernization

### 7.1 Backend-neutral public API

- [ ] keep high-level certificate APIs backend-neutral where practical;
- [ ] avoid leaking backend implementation types unless intentionally low-level;
- [ ] centralize PEM/DER/key/certificate loading/normalization;
- [ ] retain OpenSSL-native acceleration only where measured/useful and semantically identical;
- [ ] make backend/algorithm capability failures explicit.

### 7.2 X.509 and CSR

- [ ] migrate/validate certificate parsing against phpseclib 4 X509;
- [ ] migrate CSR work to phpseclib 4’s dedicated CSR model where beneficial;
- [ ] validate subject/issuer/SAN/basic-constraints/path-length/key-usage/EKU consistently;
- [ ] validate serial/validity bounds;
- [ ] add certificate-profile validation for server/client/code-signing use;
- [ ] preserve deterministic certificate/key matching.

### 7.3 Chain validation

- [ ] replace/wrap current temp-file/OpenSSL-purpose flow with a clearer chain model;
- [ ] avoid unnecessary one-temp-file-per-CA behavior;
- [ ] bound chain length/depth;
- [ ] validate validity/basic constraints at each level;
- [ ] define trust-anchor treatment;
- [ ] reject malformed/duplicate/looping chains;
- [ ] provide typed diagnostics where callers need them;
- [ ] no hidden AIA fetching.

### 7.4 CRL/revocation

- [ ] evaluate first-class phpseclib-4 CRL parse/sign/verify support;
- [ ] support caller-provided revocation material without hidden network access;
- [ ] keep OCSP/network revocation out of core unless explicitly bounded/configured;
- [ ] document revocation limits.

### 7.5 PFX/PKCS#12

- [ ] evaluate/implement phpseclib-4 PFX as the portable model;
- [ ] retain compatibility with OpenSSL-generated PKCS#12 fixtures;
- [ ] handle password errors without leakage;
- [ ] round-trip certificate/private key/friendly name/CA chain;
- [ ] bound input size/counts.

### 7.6 CMS

- [ ] add CMS sign/verify/encrypt/decrypt only if phpseclib 4 provides a clean stable boundary and interoperability coverage is practical;
- [ ] do not invent a parallel CMS parser;
- [ ] add independent fixtures if shipped.

### 7.7 SPKAC

- [ ] expose only if a concrete library use case exists.

---

## 8. JOSE/JWT/JWS/JWE hardening

### Algorithm policy

- [ ] complete the unified explicit algorithm/allowlist audit;
- [ ] never accept `alg=none`;
- [ ] prevent HS↔RSA/EC/EdDSA confusion;
- [ ] reject incompatible key type/curve/size;
- [ ] enforce minimum RSA modulus policy;
- [ ] validate EC curves exactly for ES256/384/512;
- [ ] validate EdDSA JWK curve/key lengths;
- [ ] preserve strict RSA-PSS semantics.

### JWS

- [ ] enforce total/segment bounds before decode;
- [ ] reject duplicate/ambiguous protected headers;
- [ ] explicitly handle/reject `crit` extensions;
- [ ] explicitly support/reject RFC 7797 `b64=false` per API;
- [ ] validate `typ`/`cty` only by caller policy;
- [ ] keep DER↔JOSE conversion strict/constant-size;
- [ ] add malformed DER/non-canonical signature adversarial tests.

### JWE

- [ ] re-audit AES-KW/RSA/ECDH/Concat-KDF/content encryption against RFC vectors;
- [ ] validate CEK/IV/tag lengths before crypto;
- [ ] preserve authenticated protected-header bytes exactly;
- [ ] reject unsupported critical/unprotected combinations;
- [ ] bound plaintext/ciphertext/token size;
- [ ] zeroize CEK/intermediate secrets where practical;
- [ ] collapse failed decryptions to stable non-oracular public failures.

### JWT policy — RFC 8725/BPC alignment

- [ ] keep issuer/audience/type checks explicit;
- [ ] enforce configured maximum lifetime;
- [ ] define leeway consistently for `iat`/`nbf`/`exp`;
- [ ] reject pathological timestamp/claim types;
- [ ] prevent cross-JWT confusion through purpose/type/context separation;
- [ ] test multi-audience and missing/duplicate claims;
- [ ] keep replay-store policy explicit.

### JWK/JWKS

- [ ] centralize public/private JWK validation;
- [ ] never include private members in public export;
- [ ] validate `kid`/`kty`/curve/modulus/exponent/`use`/`key_ops`/`alg`/`x5c` coherently;
- [ ] bound key count/field sizes;
- [ ] reject duplicate-`kid` ambiguity;
- [x] preserve RFC 7638 canonical thumbprints in migrated readiness paths;
- [ ] complete RSA/EC/OKP public/private round-trip coverage.

---

## 9. Remote JWKS / OpenID discovery hardening

- [ ] keep HTTPS-only by default;
- [ ] prohibit credentials/fragments;
- [ ] enforce issuer-host match or explicit allowlist;
- [ ] validate DNS-resolved IP addresses against private/reserved ranges;
- [ ] define DNS-rebinding/connected-IP enforcement seam;
- [ ] require redirects disabled or explicitly bounded/revalidated;
- [ ] add timeout guidance/contracts where supported;
- [ ] retain hard response byte/depth/key limits;
- [ ] add JSON member/count limits;
- [ ] evaluate conditional refresh (`ETag`/`Last-Modified`);
- [ ] preserve `no-store`/`no-cache` semantics;
- [ ] define stale-if-error behavior;
- [ ] prevent cache-key collisions;
- [ ] structurally revalidate cached values;
- [ ] redact sensitive backend URI/network details;
- [ ] add SSRF/rebinding/redirect adversarial fixtures.

---

## 10. DPoP / OpenID token validation

### DPoP

- [ ] preserve RFC 9449 `htu` normalization;
- [ ] separate future skew from maximum proof age;
- [ ] keep `htm`/`htu`/`iat`/`jti`/`ath`/nonce/JWK binding strict;
- [ ] require public-only asymmetric header JWK;
- [ ] validate JWK/algorithm compatibility before signature work;
- [ ] keep replay consume keyed by thumbprint + `jti` with precise expiry;
- [ ] add nonce helpers only if generic/protocol-correct;
- [ ] add RFC/negative vectors.

### OpenID ID token validation

- [ ] audit issuer/audience/azp/nonce/time validation;
- [ ] verify/add `at_hash`/`c_hash` as applicable;
- [ ] keep signing algorithm caller-configured;
- [ ] reject algorithm/key substitution;
- [ ] use the hardened Remote JWKS boundary.

---

## 11. Purpose tokens, opaque tokens and refresh rotation

- [x] consolidate overlapping password-reset/email-verification/action/passwordless mechanics over one generic purpose-token engine;
- [x] retain dedicated convenience classes only where they add domain-safe defaults;
- [x] use canonical token-id generation;
- [x] make expiration/not-before/result semantics consistent;
- [x] support KeyRing active/fallback verification;
- [x] enforce mandatory purpose/context domain separation;
- [ ] complete the later refresh-token concurrency/reuse audit;
- [ ] retain small abstract storage contracts;
- [ ] keep CAS/atomicity requirements explicit;
- [ ] do not add DB/cache adapters to core;
- [ ] add concurrency/reuse/race contract tests.

---

## 12. Secret/key generation and derivation

- [ ] finish consolidation of `RandomBytesGenerator`, `NonceGenerator`, `SaltGenerator`, `TokenMaterialGenerator` and `KeyMaterialGenerator` so each has a distinct purpose and no remaining duplicate encoding policy;
- [ ] extend explicit output-encoding policy beyond canonical key material only where useful rather than adding boolean-format flags;
- [ ] finish named profiles for master/HMAC/CSRF/signed-URL/token-id/nonce use where they improve safety;
- [x] use at least 256-bit entropy for general master/application/HMAC-style secrets unless a primitive specifies another exact length;
- [x] make key derivation HKDF/domain-separated and label-driven;
- [x] prevent accidental derived-key reuse across purposes;
- [x] validate derivation output lengths;
- [x] include RFC 5869 HKDF vectors;
- [ ] finish the library-wide sensitive-parameter pass;
- [ ] use `sodium_memzero()` for mutable temporary state where practical without overstating PHP erasure guarantees.

---

## 13. Password subsystem

### Hashing

- [ ] finalize Argon2id as recommended/new-write policy;
- [ ] decide whether Argon2i remains selectable for new writes while retaining legacy verification;
- [ ] retain bcrypt only as explicit compatibility if required;
- [ ] preserve strict bcrypt >72-byte new-hash rejection and document verification behavior;
- [ ] preserve `password_needs_rehash()` semantics;
- [ ] expose measured policy profiles only if justified;
- [ ] test malformed/unsupported hashes without warnings.

### Peppering

- [ ] do not add implicit peppering without a versioned rotation/storage model;
- [ ] if introduced, make peppering explicit, key-id aware and rotation-safe;
- [ ] never silently alter stored password semantics.

### Compromised-password checking

- [ ] evaluate optional HIBP k-anonymity checker over existing PSR HTTP contracts;
- [ ] never send raw passwords;
- [ ] bound response/time/format;
- [ ] remain optional/offline-safe.

### Password policy/generation

- [ ] review entropy and Unicode/byte semantics;
- [ ] distinguish password policy from passphrase generation;
- [ ] avoid low-value composition rules;
- [ ] keep generation CSPRNG-only/unbiased.

---

## 14. Data protection / envelope / wrapped secrets

- [ ] complete the library-wide persisted/wire-format inventory;
- [x] freeze the critical 2.x protected/signed fixtures before refactoring;
- [x] retain read/verify support for frozen valid 2.x material already covered by tests;
- [x] do not bump formats merely because package major changed;
- [ ] complete metadata-authentication audit across every protected format;
- [ ] reject unknown mandatory metadata consistently;
- [ ] enforce all payload/ciphertext/metadata bounds;
- [ ] prevent attacker-controlled algorithm selection;
- [ ] expose fallback/reprotect signals consistently across protected formats;
- [ ] add migration/re-protection helpers where needed;
- [ ] keep public failures non-oracular;
- [ ] complete truncation/corruption/metadata/key/AAD/purpose adversarial matrix.

---

## 15. Primitive audit

### AEAD / secret box / public-key box

- [ ] verify all nonce/key/tag lengths before native calls;
- [ ] minimize unsafe caller-supplied nonce surfaces;
- [x] keep AEGIS capability detection explicit and verify a modern positive runtime;
- [ ] add authoritative vectors where useful;
- [ ] normalize primitive failures to Epicrypt exceptions.

### MAC/signature

- [ ] complete constant-time verification audit;
- [ ] validate minimum HMAC key lengths everywhere;
- [ ] prevent arbitrary-string algorithm downgrade;
- [ ] keep detached inputs/output encoding explicit.

### Ristretto / X25519 / Ed25519 / key exchange

- [ ] validate invalid/all-zero shared-secret cases;
- [ ] validate exact key lengths;
- [ ] preserve domain separation in derived session keys;
- [ ] benchmark realistic backend choices only.

### Internal codecs

- [ ] eliminate duplicate Base64URL/JSON/binary-key validation implementations;
- [ ] reject non-canonical encodings where security-relevant;
- [ ] bound JSON depth/size/count;
- [ ] keep internal helpers internal unless a stable public use exists.

---

## 16. Exception/result model and secret hygiene

- [ ] inventory/normalize exception hierarchy;
- [ ] distinguish configuration/key-resolution/input-format/verification/backend failures;
- [ ] expose stable non-sensitive public messages;
- [ ] preserve backend exceptions as previous only for useful diagnostics;
- [ ] never interpolate secret material into exceptions;
- [ ] avoid full attacker-controlled tokens/URLs in errors;
- [ ] finish `#[SensitiveParameter]` coverage;
- [ ] audit serialization/debug surfaces for leaks;
- [ ] prefer readonly immutable results/config;
- [ ] prefer typed result enums/reasons over string parsing;
- [ ] avoid redundant throwing/result API explosion.

---

## 17. Bounds and denial-of-service policy

Define and test centralized limits for compact JOSE bytes/segments, headers/claims, JWK/JWKS, remote discovery, signed payloads/URLs, certificate/CSR/CRL/PFX/CMS, chains, protected payload metadata/ciphertext, file framing/chunks, identifiers, and password/passphrase inputs.

- [ ] fail before expensive crypto where possible;
- [ ] make only legitimately adjustable limits configurable;
- [ ] avoid unsafe `0 = unlimited` parser modes.

---

## 18. Signed URL review

- [ ] complete the broader canonicalization/bounds audit while preserving duplicate-query/reserved-key rejection;
- [ ] freeze percent-encoding/case/path vectors;
- [ ] verify host/scheme/default-port binding;
- [ ] verify method/expiration boundaries;
- [ ] bound pair count/key/value/total URL length;
- [x] preserve raw-secret v2 verification/wire compatibility;
- [x] support active/fallback `KeyRing` rotation;
- [x] report fallback-key use;
- [x] remain independent of Webrick/Foundation routing.

---

## 19. API/namespace cleanup for the major

- [ ] review top-level domain boundaries;
- [ ] resolve duplicate `KeyPurpose` concepts where semantics overlap;
- [ ] eliminate duplicate policy/codec helpers;
- [ ] standardize method vocabulary;
- [ ] prefer immutable configuration/results;
- [ ] reduce generic `Manager` names where a precise capability is better;
- [ ] keep constructors small and validate at construction;
- [x] no service locator/global mutable registry;
- [x] no framework/container coupling;
- [ ] complete the 2.x→3.0 migration table.

---

## 20. Tests and security validation

### Required matrices

- [x] PHP 8.4 prefer-lowest;
- [x] PHP 8.4 prefer-stable;
- [x] PHP 8.5 prefer-lowest;
- [x] PHP 8.5 prefer-stable;
- [x] clean production install;
- [x] Epicrypt core without Pathwise installed;
- [x] Pathwise 4 dev/integration tests;
- [x] phpseclib 4 native tests;
- [ ] explicit OpenSSL capability matrix where behavior differs;
- [x] modern libsodium/AEGIS positive environment;
- [ ] Windows matrix where path/certificate behavior is meaningful.

### Interoperability

- [x] JWS RSA/EC/EdDSA;
- [x] RSA-PSS;
- [x] JWE migrated key-management/content-encryption paths;
- [x] JWK/JWKS migrated import/export paths;
- [ ] DPoP fixtures;
- [ ] X.509/CSR/PFX/CMS independent fixtures;
- [x] frozen Epicrypt 2.x protected/signed compatibility fixtures.

### Mutation/security-critical testing

- [x] stream `SecretStream`/`FileProtector` data-protection paths;
- [x] phpseclib-4 JOSE/key-signature boundary;
- [x] key-set readiness/rotation;
- [ ] remote JOSE DNS/redirect policy after Phase E implementation;
- [ ] certificate chain/PFX/CMS parsers after Phase F implementation;
- [x] purpose-token replacement for Foundation simple HMAC crypto.

### Fuzz/property/adversarial tests

- [ ] compact JOSE parser;
- [ ] JSON/JWK/JWKS validation;
- [ ] protected payload framing;
- [ ] signed URL parser/canonicalization;
- [ ] certificate/PEM/PFX bounded corpus;
- [ ] authenticated-format truncation/corruption/bit-flips;
- [ ] randomized KeyRing active/fallback interleaving;
- [x] stream short-read/short-write/exception/failed-publication behavior for completed stream/local boundaries.

### Static/security gates

- [x] PHPStan/Psalm clean on current verified batch;
- [x] PHPForge architecture/lint/security/refactor gates clean on current verified batch;
- [x] no skipped tests except explicit capability-negative cases;
- [x] Composer audit/security checks green on current verified batch;
- [ ] final dependency license/security review;
- [ ] final fixture/log secret-leak review.

---

## 21. Performance plan

Maintain 2.1/current-main baselines for AEAD, SecretStream, data protection, password hashing, JOSE, JWK/JWKS, Remote JWKS warm cache, KeyRing, certificates/PKCS#12 and package boot/install footprint as later phases touch them.

### 3.0 attribution

- [x] stream API vs prior Pathwise-backed/local design evidence;
- [x] local path wrapper overhead above stream core;
- [x] phpseclib-4 migration benchmark evidence for migrated JOSE paths;
- [ ] phpseclib 4 vs OpenSSL-native backend where both remain after PKI review;
- [ ] PFX/CMS/X509 parse costs;
- [ ] large KeyRing lookup benchmark;
- [ ] purpose-token vs Foundation codec benchmark if useful before Foundation migration;
- [x] no-Pathwise production install/boot evidence;
- [x] Pathwise 4 integration overhead kept separate from crypto work.

Never weaken validation or limits for benchmark wins.

---

## 22. Documentation

- [x] architecture/ownership/dependency DAG;
- [ ] complete final installation/optional-integration guide;
- [x] Pathwise 4 explicit-stream integration guidance;
- [x] phpseclib 4 migration/dependency notes for completed migration;
- [x] key generation/derivation/rotation guidance for completed boundaries;
- [x] purpose-token/signed-payload guidance;
- [ ] finish consolidated JOSE security policy after Phase E;
- [ ] DPoP/remote JWKS deployment guidance after Phase E;
- [ ] certificate/CSR/chain/PFX/CMS docs after Phase F;
- [ ] finalize password policy docs after Phase G;
- [x] persisted-format/package-version distinction;
- [ ] final exceptions/safe-logging guide;
- [x] benchmark/performance methodology for completed A–C work;
- [ ] full Epicrypt 2.x→3.0 migration guide before RC.

Documentation must distinguish package/API version, cryptographic wire/storage format version, and algorithm/key-rotation version.

---

## 23. Foundation follow-up acceptance

After Epicrypt 3 reaches RC:

- [ ] Foundation changes `infocyph/epicrypt` to `^3.0`;
- [ ] Foundation keeps `infocyph/pathwise ^4.0` independently;
- [ ] Composer resolves Epicrypt + Pathwise + OTP without hacks;
- [ ] Foundation Point 26.5 Pathwise tests become installable/runnable;
- [ ] Foundation removes `Auth\Support\HmacTokenCodec`;
- [ ] Foundation reduces parallel simple signed-token crypto;
- [ ] Foundation uses Epicrypt key derivation for generic crypto;
- [ ] Foundation OAuth signing-key resolver delegates crypto readiness to Epicrypt;
- [ ] Foundation environment-secret generation delegates material generation to Epicrypt;
- [ ] Foundation `EnvironmentFileProtector` becomes only an application/path/config/CLI policy adapter over Epicrypt local/stream protection rather than a second staging protocol;
- [ ] Foundation Epicrypt adapters become contract/claim mappings rather than cryptographic implementations;
- [ ] OTP remains independently composable with no circular Composer dependency;
- [ ] Foundation PHP 8.4/8.5 CI passes with Epicrypt 3 + Pathwise 4 + current OTP.

---

## 24. Implementation sequence

### Phase A — freeze baselines and formats

1. [x] capture current 2.x persisted-format fixtures and comparable benchmark baselines;
2. [x] enumerate public API slated for removal/rename;
3. [x] document dependency/ownership decisions;
4. [x] prove durable payload/file/token formats before refactoring.

### Phase B — break dependency coupling

5. [x] redesign `SecretStream`, `FileProtector`, `FileHasher` around streams;
6. [x] remove Pathwise imports from production source;
7. [x] move Pathwise to `require-dev ^4.0` for interop only;
8. [x] add no-Pathwise production clean-install gate;
9. [x] add Pathwise 4 explicit-context stream interop test.

### Phase C — phpseclib 4

10. [x] raise phpseclib to native `^4.0.1` floor;
11. [x] migrate namespaces/types/exceptions;
12. [x] validate RSA/PS/EC/JWK/JWE migrated paths;
13. [x] run JOSE interoperability and migration benchmarks;
14. [x] supersede PR #29.

### Phase D — Foundation-facing crypto/key boundary consolidation

15. [x] refine KeyRing/readiness/key derivation;
16. [x] add generic signing-key-set/keypair validation;
17. [x] consolidate purpose/timed signed-token API;
18. [x] add Foundation-equivalent replacement fixtures for simple HMAC/timed tokens;
19. [x] add signed-URL KeyRing rotation support;
19a. [x] centralize application/environment secret material generation and explicit encoding;
19b. [x] prove one safe Epicrypt local protected-file publication layer so Foundation does not need duplicate crypto staging.

### Phase E — JOSE/network hardening

20. [ ] centralize JOSE limits/algorithm/key validation;
21. [ ] harden Remote JWKS DNS/redirect/network policy;
22. [ ] audit DPoP/OpenID validation;
23. [ ] expand adversarial/interoperability tests.

### Phase F — certificate/PKI modernization

24. [ ] migrate certificate loaders/model to phpseclib 4 where beneficial;
25. [ ] restructure CSR/chain validation;
26. [ ] implement/modernize CRL support if accepted;
27. [ ] migrate PKCS#12 to PFX model;
28. [ ] add CMS only if scope/security/interop review passes;
29. [ ] benchmark OpenSSL/phpseclib backend choices.

### Phase G — password/secret/data-protection cleanup

30. [ ] finalize Argon2id/new-write policy;
31. [ ] finish remaining secret/key-generator consolidation beyond the Foundation-facing Batch 4 boundary;
32. [ ] audit protected payload/envelope/wrapped-secret formats and migration signals;
33. [ ] finish exception/sensitive-parameter/zeroization pass.

### Phase H — release integration

34. [ ] run final full PHPForge CI/mutation/interoperability matrix;
35. [ ] run final performance attribution;
36. [ ] publish migration guide/docs;
37. [ ] create Epicrypt 3 RC;
38. [ ] integrate RC into Foundation and run full Foundation 3 gates;
39. [ ] resolve ecosystem incompatibilities;
40. [ ] tag Epicrypt 3.0 only when Foundation + Pathwise 4 + OTP composition is green.

---

## 25. Explicit release gates

**These remain intentionally unchecked until Phase H validates the final release candidate, even when the current development head passes the corresponding CI lane.**

### Dependency gates

- [ ] no production dependency on Pathwise;
- [ ] no dependency on OTP;
- [ ] native phpseclib 4 requirement/implementation;
- [ ] clean Composer resolution alongside Pathwise 4 and OTP in Foundation;
- [ ] no aliases/replaces hiding incompatible metadata.

### Correctness/security gates

- [ ] durable 2.x artifacts remain readable/verifiable or have a secured migration path;
- [ ] stream crypto handles short reads/writes/failures deterministically;
- [ ] failed authentication/encryption/decryption never publishes output;
- [ ] deterministic active/fallback key rotation;
- [ ] no private JWK/key leakage through public export/results/errors;
- [ ] JOSE algorithm confusion rejected;
- [ ] RSA-PSS/EC/EdDSA interoperability passes;
- [ ] Remote JWKS SSRF/redirect/DNS bounded;
- [ ] DPoP replay/binding adversarial tests pass;
- [ ] certificate/CSR/chain/PFX independent fixtures pass;
- [ ] Argon2id-first password policy and legacy verification pass;
- [ ] sensitive parameter/error/log review passes;
- [ ] parser/input limits enforced before expensive work.

### Runtime/isolation gates

- [ ] no global mutable key/storage/token registry;
- [ ] repeated/interleaved operations retain no prior secret/key/request state;
- [ ] Pathwise 4 integration uses caller-owned contexts/streams only;
- [ ] parallel/Fiber tests pass where relevant;
- [ ] reusable value/config objects are immutable or explicitly documented.

### QA gates

- [ ] PHP 8.4/8.5 lowest/stable green on final RC;
- [ ] clean production install green;
- [ ] no-Pathwise core install/test green;
- [ ] Pathwise 4 integration green;
- [ ] phpseclib 4 native matrix green;
- [ ] independent JOSE interoperability green;
- [ ] AEGIS positive capability job green;
- [ ] security-critical mutation thresholds green;
- [ ] analyzers/security/audit clean;
- [ ] benchmarks recorded with no unexplained material regression.

### Ecosystem gates

- [ ] Foundation can raise Epicrypt to `^3.0` while retaining Pathwise `^4.0`;
- [ ] Foundation Point 26.5 can complete without dependency conflict;
- [ ] Foundation crypto duplication identified here is removed/reduced;
- [ ] OTP remains independent and Foundation OTP/Epicrypt composition is green.

---

## 26. Non-goals for 3.0

- no OTP algorithms/WebAuthn implementation in Epicrypt;
- no application OAuth authorization server;
- no database/cache/storage adapters in core;
- no cloud-vendor KMS/Vault SDK dependencies in core;
- no global service locator/key registry;
- no new PASETO/proprietary token family merely for feature count;
- no hidden AIA/CRL/OCSP network fetching;
- no broad CMS/SPKAC surface without concrete interoperability/security justification;
- no phpseclib 3 compatibility shim;
- no Pathwise 3 compatibility layer;
- no wire-format v3 merely to match package version 3.

---

## 27. Final target

```text
application policy / HTTP / persistence / runtime
                    Foundation
                        │
        ┌───────────────┼───────────────┐
        │               │               │
     Epicrypt 3       OTP 6.x       Pathwise 4
        │                               │
  phpseclib 4                   Flysystem/storage
```

Epicrypt owns security primitives, cryptographic formats and reusable key/token/certificate mechanics. OTP owns MFA. Pathwise owns storage. Foundation composes them.

Epicrypt 3 is successful when Foundation no longer maintains a second cryptographic token/key implementation and no package constraint prevents Epicrypt, OTP and Pathwise from being installed together.
