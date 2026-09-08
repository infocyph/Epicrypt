# Epicrypt 3.0 — Final Development Plan

## Status

Target release: **Epicrypt 3.0**

Planning branch: `epicrypt-3/architecture-plan`

Baseline audited from current `main` at `f80092978328cccaef0d2233b08ce95b453dd90a`.

Implementation status: **Phase A + Phase B in progress**.

Latest implementation batch: **A+B Batch 1** — `0538cec0eb89b1b954bbd04cb0c0327d502031b3`.

### Progress ledger

#### 2026-09-08 — Phase A+B Batch 1

Completed in this batch:

- moved `SecretStream`, `FileProtector` and `FileHasher` to native caller-owned PHP stream cores while retaining local-path convenience APIs;
- removed all production Pathwise imports and removed Pathwise from Composer `require`;
- moved Pathwise to `require-dev ^4.0` solely for explicit interoperability tests;
- added an internal native stream/local-file boundary with bounded short-read/short-write handling, shared input locking and atomic local output publication;
- preserved the existing `ep2` protected-file framing and added a frozen Epicrypt 2.x protected-file compatibility fixture;
- retained the existing frozen 2.x string-protection fixture and added a frozen 2.x signed-payload fixture;
- added `ProtectionMetadata` so stream operations return metadata without inventing a fake output path/value;
- added a public-API inventory for intentional 3.0 removals/renames before later breaking changes land;
- added a Pathwise 4 `StorageContext` interoperability test using two independent contexts with the same logical disk name to prove no ambient Pathwise state is required;
- added a production-only no-Pathwise smoke script and an architecture test preventing production Pathwise imports.

Validation performed for Batch 1:

- targeted PHP 8.4 syntax checks passed for the new/changed stream implementation and tests;
- targeted runtime checks passed for SecretStream stream round-trip, FileProtector stream round-trip, FileHasher SHA/BLAKE2b stream hashing and decryption of the frozen 2.x protected-file artifact;
- full Composer/Pest/PHPForge CI was **not** run from the chat environment and remains a required repository CI validation.

Still open before Phase A+B can close:

- capture/record numeric Epicrypt 2.1/current-main benchmark baselines before performance comparisons;
- add and run the production-only `composer install --no-dev` no-Pathwise CI gate using `tests/Smoke/core-no-pathwise.php`;
- run the complete test/static/security matrix with Pathwise 4 installed and resolve any findings;
- add/compare dedicated stream-vs-local-wrapper benchmarks.

Primary ecosystem goals:

- unblock Foundation 3 from the Epicrypt 2.1 → Pathwise `^3.1` constraint;
- keep the dependency graph acyclic across Epicrypt, Pathwise, OTP and Foundation;
- migrate Epicrypt natively to Pathwise 4 integration semantics where integration is useful;
- migrate Epicrypt natively to phpseclib 4 rather than carrying a phpseclib 3 compatibility shim;
- move reusable cryptographic/token/key-management mechanics out of Foundation and into Epicrypt where they belong;
- harden security boundaries, formats, limits, failure semantics and remote JOSE behavior;
- preserve compatibility with persisted Epicrypt 2.x encrypted/signed material even though the PHP API may break for the 3.0 major.

This is a **major release**. Source/API backward compatibility is not a release constraint. **Persisted cryptographic compatibility is a separate release constraint and must not be broken casually.** Existing encrypted files, protected payloads, wrapped secrets, signed payloads and tokens that are intentionally documented as durable must remain readable/verifiable unless a concrete security reason requires retirement and a migration path is provided.

---

## 1. Final ownership model

Epicrypt 3 is a lower-level security/cryptography library. It must not become an application framework, storage engine or MFA system.

### Epicrypt owns

- cryptographic primitives and safe cryptographic composition;
- secret/key generation and deterministic key derivation;
- key identifiers, key rings, key eligibility, rotation and verification readiness;
- versioned/signed/encrypted payload formats;
- generic purpose-bound timed tokens;
- password hashing, verification, rehash policy, password generation and password-policy helpers;
- JWT/JWS/JWE/JWK/JWKS, DPoP and OpenID token cryptographic validation;
- opaque-token cryptographic material and generic refresh-token rotation mechanics;
- certificate/key/CSR/chain/PFX/CMS/PKI cryptographic operations;
- local/stream data-protection transforms and their framing/authentication rules;
- generic integrity hashing/MAC/signature operations;
- strict cryptographic limits, algorithm policy and safe result/exception types.

### Pathwise owns

- storage configuration and storage contexts;
- local/remote filesystem adapters;
- path routing, filesystem schemes and storage identity;
- file localization/staging/commit mechanics for storage adapters;
- safe generic filesystem reading/writing;
- uploads/downloads, archive/sync/retention and storage policy.

Epicrypt must not own a second storage registry or rely on Pathwise global mounts.

### OTP owns

- OTP algorithms and provisioning;
- TOTP/HOTP/AOTP domain behavior;
- replay/claim/consume semantics for OTP;
- recovery-code domain behavior where it is OTP-specific;
- passkey/WebAuthn ceremonies and MFA orchestration owned by OTP;
- OTP-specific persistence/cache contracts.

Epicrypt **must not depend on OTP** in production. OTP should also remain capable of operating without Epicrypt unless a future explicit optional adapter has a compelling reason.

### Foundation owns

- application configuration and environment selection;
- DI/provider graph and runtime lifecycle;
- application paths and CLI commands;
- HTTP/router/session/authentication/application OAuth orchestration;
- account/user/authorization domain behavior;
- database/cache repositories and transactions;
- application audit policy and diagnostics;
- choosing and configuring Epicrypt/OTP/Pathwise capabilities;
- mapping lower-layer results into Foundation contracts and HTTP/application behavior.

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

This is the release architecture. Do not solve the current Foundation conflict by widening Epicrypt to `pathwise ^3.1 || ^4.0`; remove the unnecessary production dependency instead.

---

## 2. Composer/dependency reset

### 2.1 Pathwise

Current Epicrypt 2.1 requires `infocyph/pathwise ^3.1`, but production use is concentrated in a small number of file-oriented classes (`FileHasher`, `SecretStream`, `FileProtector`). This is too much dependency weight and causes the current Foundation incompatibility.

For Epicrypt 3:

- [x] remove `infocyph/pathwise` from production `require`;
- [x] add `infocyph/pathwise: ^4.0` to `require-dev` only for integration/interoperability tests where useful;
- [x] do not expose or depend on Pathwise static/global mount APIs;
- [x] make file crypto **stream-first** so Foundation/Pathwise can supply streams without Epicrypt knowing storage topology;
- [x] keep local path convenience APIs where useful, implemented over Epicrypt-owned local stream/path helpers rather than Pathwise classes;
- [x] add examples/tests showing Pathwise 4 `StorageContext`/Flysystem streams feeding Epicrypt stream APIs without cross-process/global state;
- [x] do not add a Pathwise `suggest` entry unless Epicrypt ships an actual public optional integration class that needs it. A dev-only interoperability dependency is preferable if core stream APIs are sufficient.

### 2.2 OTP

- [ ] do not add OTP to Epicrypt `require` or `require-dev` merely for Foundation integration;
- [ ] keep generic cryptographic facilities in Epicrypt and MFA semantics in OTP;
- [ ] document that Foundation composes the two packages rather than either package depending on the other;
- [ ] if OTP needs deterministic subkeys, prefer a small generic input/key contract or application-provided derived key rather than OTP importing Epicrypt as a mandatory dependency.

### 2.3 phpseclib

Current Epicrypt uses phpseclib 3 namespaces and the current Dependabot PR #29 only widens Composer to `^3.0 || ^4.0`. That is insufficient because phpseclib 4 changes namespace and behavior.

For Epicrypt 3:

- [ ] require `phpseclib/phpseclib ^4.0.1` (or the current stable 4.x floor selected at implementation time);
- [ ] migrate code natively from `phpseclib3\...` to `phpseclib4\...`;
- [ ] do not ship a dual phpseclib 3/4 compatibility layer;
- [ ] supersede/close Dependabot PR #29 once the native 4.x migration lands;
- [ ] audit all phpseclib calls for v4 exception semantics instead of assuming v3 `false` returns;
- [ ] handle password-protected key loading with the correct v4 password-needed/error types;
- [ ] revalidate RSA-PSS behavior and salt-length handling;
- [ ] migrate `BigInteger`, `PublicKeyLoader`, RSA private/public keys and any other direct phpseclib types to v4;
- [ ] add phpseclib 4-specific interoperability/regression tests.

### 2.4 extensions and PSR packages

- [ ] retain PHP `^8.4` as the Epicrypt 3 floor;
- [ ] continue testing PHP 8.4 and 8.5;
- [ ] review whether `ext-openssl` remains mandatory after the phpseclib 4 certificate pass. Keep it mandatory if Epicrypt intentionally uses OpenSSL-native acceleration/backends; otherwise make capabilities explicit rather than retaining an unnecessary hard extension dependency;
- [ ] retain `ext-sodium` for modern symmetric/public-key primitives and AEGIS capability where supported;
- [ ] retain PSR clock/HTTP/cache contracts only where public capabilities use them;
- [ ] no framework-specific dependency.

---

## 3. Stream-first file/data protection and Pathwise decoupling

### Current problem

`SecretStream`, `FileProtector` and `FileHasher` import Pathwise `SafeFileReader`/`SafeFileWriter`, although the cryptographic contract is mostly local/stream based. That makes storage a mandatory dependency of the crypto library and prevents Foundation from independently selecting Pathwise 4.

### Target design

```text
Path/file/storage owner
        ↓
PHP stream/resource
        ↓
Epicrypt stream crypto/integrity engine
        ↓
PHP stream/resource
        ↓
caller/Pathwise commits destination
```

### Required changes

- [x] add stream-native `SecretStream` encrypt/decrypt entry points;
- [x] add stream-native `FileProtector`/protected-stream entry points;
- [x] add stream-native `FileHasher` hashing/verification entry points;
- [x] keep bounded chunking and exact framing validation;
- [x] validate stream readability/writability and fail with Epicrypt exceptions;
- [x] guarantee cleanup/zeroization of internal state in normal and exceptional paths;
- [x] avoid retaining input/output stream references beyond one operation;
- [x] keep path convenience methods as wrappers over stream operations;
- [x] for local path replacement, preserve existing destination on crypto failure and use safe sibling staging/commit semantics;
- [x] do not accept arbitrary Pathwise scheme strings in the core path APIs. Storage-backed callers should resolve/open streams explicitly;
- [x] add Pathwise 4 integration tests using independent `StorageContext` instances with identical disk names to prove Epicrypt has no ambient storage state;
- [ ] verify remote/adapter streams can be processed without whole-file buffering when the caller provides appropriate streams;
- [ ] benchmark local paths and streams separately.

### File format compatibility

- [x] continue reading Epicrypt 2.x protected-file framing;
- [x] remove misleading protected-file error text that hard-codes “Epicrypt 2.0” where the concern is a format version;
- [x] separate `package version` from `wire/storage format version` explicitly in the 3.0 API inventory/plan;
- [x] do not introduce a new protected-file format merely because the package major changes;
- [ ] if a v3 format is justified, implement **read old + read new + write new**, publish deterministic migration/re-protection tooling/examples, and include fixed cross-version test vectors.

---

## 4. Foundation → Epicrypt ownership transfer

The Foundation follow-up after Epicrypt 3 should delete or reduce framework-level cryptographic implementations. Epicrypt 3 must expose the lower-level APIs needed for that cleanup.

### 4.1 Remove Foundation `HmacTokenCodec`

Foundation currently has `Auth\Support\HmacTokenCodec`, implementing its own HMAC-SHA256 compact format, Base64URL codec and JSON verification.

Epicrypt 3 must provide a complete generic replacement through `SignedPayload` / a refined purpose-token API.

- [ ] provide an ergonomic purpose-bound signed payload/timed-token API with typed verification results;
- [ ] support context/domain separation, `iat`, `exp`, token id, purpose and caller claims without Foundation recreating signing mechanics;
- [ ] support active/fallback `KeyRing` verification and report the key used;
- [ ] expose stable failure reasons such as invalid, expired, not-yet-valid, wrong-purpose/context and unsupported-format without leaking key details;
- [ ] ensure token IDs can use Epicrypt `TokenMaterialGenerator` rather than raw application cryptography;
- [ ] Foundation should delete `HmacTokenCodec` and its parallel simple crypto format once its callers are migrated.

### 4.2 Reduce Foundation simple timed-token implementations

Foundation currently owns generic timing/purpose/signing logic in `AbstractSimpleTimedTokenService` and similar simple access/refresh/passwordless/reset/email-verification paths.

- [ ] move generic timed-token issue/verify mechanics into Epicrypt;
- [ ] keep Foundation claim mapping, account lookup, repositories, revocation and application-contract adaptation;
- [ ] do not move user/account/authentication orchestration into Epicrypt;
- [ ] allow Foundation adapters to become small claim/result translators.

### 4.3 Key derivation

Foundation currently uses raw `hash_hmac()` to derive at least one OTP recovery-code key.

- [ ] make `KeyDeriver` the canonical Epicrypt HKDF/domain-separated derivation boundary;
- [ ] provide explicit labels/context/salt and output-length policy;
- [ ] add helpers for deriving independent application subkeys from one master secret without key reuse across token/session/recovery purposes;
- [ ] Foundation should use this boundary where the key derivation is application composition;
- [ ] OTP-specific recovery-code mechanics remain OTP-owned.

### 4.4 Environment secret generation

Foundation `EnvironmentSecretManager` should continue owning `.env` selection/editing and config-cache invalidation, but not secret-generation rules.

- [ ] expose/retain a clear Epicrypt master-secret/token-secret generator returning appropriate raw/Base64URL/hex material;
- [ ] provide minimum-entropy/length guidance and tests;
- [ ] Foundation should ask Epicrypt for the secret and only write it to `.env`.

### 4.5 Environment-file protection

Foundation `EnvironmentFileProtector` already delegates encryption to Epicrypt but duplicates crypto-adjacent staging/backup/rollback logic.

Target split:

- Foundation: resolve app-relative input/output, CLI flags, environment/key locator, config-cache invalidation.
- Epicrypt: authenticated protection/unprotection and protection metadata.
- Pathwise/local caller: generic storage atomicity/staging where applicable.

- [ ] make Epicrypt’s protected stream/file operation safe enough that Foundation does not build another cryptographic staging protocol;
- [ ] preserve target-on-failure guarantees;
- [ ] preserve restrictive file permissions for local secret outputs;
- [ ] keep symlink/path policy at the application/storage layer rather than hiding application path rules inside Epicrypt.

### 4.6 OAuth/JWT signing-key readiness

Foundation currently loads configured OAuth key files, builds an Epicrypt `KeyRing`, generates/verifies a readiness JWT and exports JWKS to prove the configured key pair is coherent.

Epicrypt 3 should own the reusable crypto/key part:

- [ ] add a generic asymmetric signing-key-set/readiness value object/service;
- [ ] validate active private key ↔ public key match without Foundation crafting a fake JWT solely for readiness;
- [ ] validate key id, algorithm, purpose, issuer and key eligibility centrally;
- [ ] expose JWKS export from the validated signing key set;
- [ ] expose typed readiness/validation failures;
- [ ] Foundation remains responsible for reading app configuration/files and recording readiness audit events;
- [ ] Foundation should stop defining crypto-only key-set semantics that duplicate Epicrypt.

### 4.7 What must **not** move from Foundation

Do not move these into Epicrypt:

- OAuth authorization-server routes/controllers/grants/consent;
- token revocation persistence, introspection policy or DB coordination;
- account/user/device repositories;
- sessions/cookies/CSRF middleware wiring;
- auth rate limiting, application audit/event policy;
- Foundation path/config/CLI behavior;
- WebAuthn/passkey ceremony logic;
- OTP factors/recovery-code domain behavior;
- HTTP response handling.

---

## 5. Key material, KeyRing and rotation redesign

`KeyRing` is already a strong lower-layer boundary but 3.0 can make it the canonical reusable key model.

- [ ] separate secret key material from public metadata in APIs/results so public JWKS/export operations never accidentally expose private material;
- [ ] ensure all secret-bearing constructor/method inputs carry `#[SensitiveParameter]` where applicable;
- [ ] centralize key-id grammar and maximum lengths;
- [ ] normalize/validate algorithm identifiers once;
- [ ] preserve exact-one-active-write-key semantics;
- [ ] preserve active/fallback read order explicitly;
- [ ] add explicit disabled/revoked/retired semantics if current `KeyStatus` cannot distinguish operational states cleanly;
- [ ] define `not_before`/`not_after` boundary behavior precisely and test exact timestamps;
- [ ] add key-use/purpose validation for JWK `use`/`key_ops` where applicable;
- [ ] add immutable/public-safe key metadata DTOs;
- [ ] add generic key-pair matching/readiness checks;
- [ ] add RFC 7638 JWK thumbprint vectors and use thumbprints consistently where they are stable identifiers;
- [ ] avoid trying every private key when a validated `kid` is available;
- [ ] keep constant-time comparison where comparing secret-derived identifiers/MACs;
- [ ] benchmark large key rings and active/fallback lookup;
- [ ] add rotation test vectors proving old fallback material remains readable/verifiable while new writes use only the active key.

### Key providers

Consider a small infra-neutral resolver contract only if it materially simplifies Foundation/KMS integration:

- [ ] evaluate `KeyProviderInterface` / `KeyResolverInterface` returning validated key material by id/purpose;
- [ ] keep environment/file/Vault/AWS/GCP specifics outside core unless implemented as optional integrations;
- [ ] never make Epicrypt responsible for application configuration discovery;
- [ ] no implicit global key registry.

---

## 6. phpseclib 4 native migration

### Namespace/API migration

At minimum migrate all current direct users:

- `Token\Jwt\AsymmetricJwt`;
- `Token\Jwt\Support\JwsSignature`;
- `Token\Jwt\Support\JweKeyManager`;
- `Token\Jwt\Jwks`;
- `Token\Jwt\Support\JwkPrivateKeyCodec`;
- any certificate/key classes selected to use phpseclib 4.

Required work:

- [ ] `phpseclib3` → `phpseclib4` namespaces;
- [ ] audit `PublicKeyLoader` exceptions and password-needed handling;
- [ ] audit RSA PKCS#1/PSS signing and verification settings;
- [ ] verify PSS salt length with independent vectors;
- [ ] verify EC key/curve handling and DER↔JOSE signature conversion;
- [ ] verify Curve25519/448 behavior where exposed and benefit from 4.0.1 timing-hardening changes;
- [ ] audit BigInteger serialization/import/export paths;
- [ ] replace boolean/`false` assumptions with typed exception handling where v4 changed behavior;
- [ ] prevent phpseclib exception messages containing sensitive key/passphrase material from being surfaced directly as public Epicrypt errors;
- [ ] benchmark key load/sign/verify/JWK conversion before and after migration.

### No dual-major compatibility layer

- [ ] no runtime namespace probes for both phpseclib 3 and 4;
- [ ] no `class_alias` compatibility bridge;
- [ ] no `^3 || ^4` production requirement for Epicrypt 3;
- [ ] migration guide should clearly state the dependency floor and any public type changes.

---

## 7. Certificate/PKI modernization

phpseclib 4 splits certificate, CSR, CRL and SPKAC concerns and adds PFX/CMS support. Epicrypt 3 should use that opportunity to clean up its certificate architecture rather than only changing imports.

### 7.1 Backend-neutral public API

- [ ] keep public certificate operations backend-neutral where practical;
- [ ] avoid leaking OpenSSL resource classes or phpseclib implementation types from high-level APIs unless intentionally low-level;
- [ ] centralize PEM/DER/key/certificate loading and normalization;
- [ ] retain OpenSSL-native acceleration only where it is measured/useful and behavior is identical;
- [ ] make backend/algorithm capability failures explicit.

### 7.2 X.509 and CSR

- [ ] migrate/validate certificate parsing against phpseclib 4 X509;
- [ ] migrate CSR work to phpseclib 4’s dedicated CSR model where it improves correctness;
- [ ] validate subject, issuer, SAN, basic constraints, path length, key usage and extended key usage consistently;
- [ ] validate serial number and validity bounds;
- [ ] add explicit certificate-profile validation for server/client/code-signing use rather than relying only on broad OpenSSL purpose checks;
- [ ] preserve deterministic certificate/key match checks.

### 7.3 Chain validation

Current chain verification writes CA material to temporary files and delegates to `openssl_x509_checkpurpose`.

- [ ] replace or wrap this with a clearer chain-verification model;
- [ ] avoid one temp file per CA when not required;
- [ ] validate chain length/depth bounds;
- [ ] validate validity windows and basic constraints at each level;
- [ ] verify trust-anchor treatment explicitly;
- [ ] reject malformed/duplicate/looping chains;
- [ ] provide typed result/failure information instead of only `bool` where callers need diagnostics;
- [ ] never auto-fetch AIA/remote certificate material unless a caller explicitly supplies a controlled fetch policy.

### 7.4 CRL/revocation

- [ ] evaluate first-class CRL parse/sign/verify support using phpseclib 4’s dedicated CRL type;
- [ ] support caller-provided revocation material without hidden network access;
- [ ] keep OCSP/network revocation out of core unless it can be bounded and explicitly configured;
- [ ] document revocation limitations clearly.

### 7.5 PFX/PKCS#12

Current `Pkcs12` uses OpenSSL functions directly.

- [ ] evaluate/implement phpseclib 4 PFX as the canonical portable import/export model;
- [ ] retain compatibility with existing OpenSSL-generated PKCS#12 fixtures;
- [ ] handle encrypted private-key/password errors without leaking password details;
- [ ] round-trip certificate, private key, friendly name and CA chain;
- [ ] enforce input-size/count bounds.

### 7.6 CMS

- [ ] add CMS sign/verify/encrypt/decrypt only if phpseclib 4 provides a clean stable boundary and the feature can be kept focused;
- [ ] do not invent a parallel CMS parser;
- [ ] add independent interoperability fixtures if shipped.

### 7.7 SPKAC

- [ ] only expose SPKAC if there is a concrete library use case; otherwise leave the phpseclib capability unused rather than expanding API breadth for completeness alone.

---

## 8. JOSE/JWT/JWS/JWE hardening

Epicrypt already owns a substantial JOSE implementation. 3.0 should consolidate and harden it rather than add another abstraction layer.

### Algorithm policy

- [ ] keep explicit algorithm enums/allowlists;
- [ ] never accept `alg=none`;
- [ ] prevent HS↔RS/EC/EdDSA key-type confusion;
- [ ] reject keys whose type/curve/size is incompatible with the selected algorithm;
- [ ] enforce a minimum RSA modulus policy for new signing/verification configuration;
- [ ] validate EC curves exactly for ES256/384/512;
- [ ] validate EdDSA JWK curve/key lengths;
- [ ] preserve strict RSA-PSS semantics.

### JWS

- [ ] enforce compact-token size and segment bounds before decoding;
- [ ] reject duplicate/ambiguous protected-header members;
- [ ] handle or explicitly reject `crit` extensions;
- [ ] handle or explicitly reject RFC 7797 `b64=false` rather than accidentally accepting it;
- [ ] validate `typ`/`cty` only according to caller policy, not by insecure inference;
- [ ] keep DER↔JOSE ECDSA conversion strict and constant-size;
- [ ] test malformed DER and non-canonical signatures.

### JWE

- [ ] re-audit AES-KW, RSA key management, ECDH/Concat-KDF and content encryption against RFC vectors;
- [ ] validate CEK/IV/tag lengths before crypto calls;
- [ ] keep authenticated protected header bytes exact;
- [ ] reject unsupported critical/unprotected header combinations;
- [ ] impose plaintext/ciphertext/token size bounds;
- [ ] zeroize CEK/intermediate shared-secret material when feasible;
- [ ] ensure all failed decryptions collapse to stable non-oracular public errors.

### JWT policy — RFC 8725/BPC alignment

- [ ] keep issuer/audience/type checks explicit;
- [ ] enforce maximum token lifetime where configured;
- [ ] define leeway consistently for `iat`, `nbf`, `exp`;
- [ ] reject pathological timestamps/claim types;
- [ ] prevent cross-JWT confusion by purpose/type/context separation;
- [ ] test multi-audience and missing/duplicate claim behavior;
- [ ] keep replay-store policy explicit rather than hidden global state.

### JWK/JWKS

- [ ] centralize public/private JWK validation;
- [ ] never include private members in public export;
- [ ] validate `kid`, `kty`, curve, modulus/exponent, `use`, `key_ops`, `alg`, `x5c` and thumbprints coherently;
- [ ] bound key counts and per-key field sizes;
- [ ] detect duplicate `kid` ambiguity when resolving;
- [ ] preserve RFC 7638 canonical thumbprints;
- [ ] add round-trip tests for RSA/EC/OKP public/private import/export.

---

## 9. Remote JWKS / OpenID discovery hardening

The current implementation already has response-size, depth, key-count, host and cache bounds. 3.0 should close remaining network-policy gaps.

- [ ] keep HTTPS-only by default;
- [ ] keep credentials/fragments prohibited;
- [ ] keep issuer-host matching or explicit allowlist;
- [ ] validate **resolved IP addresses** for DNS hostnames, not only literal IP input, so private/reserved-address SSRF cannot bypass hostname validation;
- [ ] define DNS rebinding behavior and make connection enforcement possible through a caller-supplied resolver/network policy if PSR-18 cannot expose the connected IP;
- [ ] require redirect behavior to be disabled or explicitly bounded/validated. Do not assume an arbitrary PSR-18 client has safe redirect defaults;
- [ ] revalidate every redirected/final URI if redirect support is introduced;
- [ ] add connect/overall timeout guidance/contracts where the HTTP client supports it;
- [ ] retain hard response byte/depth/key limits;
- [ ] add JSON member/count limits in addition to depth;
- [ ] support conditional refresh (`ETag`/`Last-Modified`) if it materially reduces network load without complicating security;
- [ ] preserve Cache-Control `no-store`/`no-cache` semantics;
- [ ] define stale-if-error behavior explicitly;
- [ ] prevent cache-key collisions between issuers/configurations;
- [ ] ensure cached values are revalidated structurally before use;
- [ ] redact backend URI/network details from stable public token failures where sensitive;
- [ ] add SSRF tests for localhost, IPv4/IPv6 private/reserved ranges, userinfo, alternate schemes, disallowed hosts, redirects and rebinding-capable resolver seams.

---

## 10. DPoP / OpenID token validation

### DPoP

- [ ] preserve RFC 9449 `htu` normalization excluding query/fragment and default ports;
- [ ] separate future clock skew from maximum proof age instead of relying only on a symmetric `abs(now - iat)` window;
- [ ] keep `htm`, `htu`, `iat`, `jti`, `ath`, nonce and JWK binding strict;
- [ ] require public-only asymmetric JWK in the DPoP header;
- [ ] validate JWK/algorithm compatibility before signature work;
- [ ] keep replay consume keyed by thumbprint + `jti` and make expiry precise;
- [ ] add nonce challenge/rotation helpers only if generic and protocol-correct;
- [ ] add RFC vectors and negative tests for method/URI canonicalization, token binding and replay.

### OpenID ID token validation

- [ ] audit issuer/audience/azp/nonce/time validation;
- [ ] verify `at_hash`/`c_hash` support where applicable, or add it if missing;
- [ ] keep signing algorithm policy caller-configured and explicit;
- [ ] reject algorithm/key substitution;
- [ ] use the same Remote JWKS hardening and key resolution boundary.

---

## 11. Purpose tokens, opaque tokens and refresh rotation

Epicrypt should provide generic token security mechanics; Foundation remains responsible for account/grant persistence and application protocol flow.

- [ ] consolidate password-reset, email-verification, action/passwordless-style purpose tokens over one generic purpose-token engine where semantics overlap;
- [ ] preserve dedicated convenience classes only when they add real domain-safe defaults;
- [ ] use a canonical token-id generator;
- [ ] make expiration/not-before/result semantics consistent;
- [ ] support KeyRing active/fallback verification uniformly;
- [ ] prevent one token purpose from being replayed as another through mandatory domain separation;
- [ ] preserve generic opaque refresh-token rotation/reuse-detection semantics;
- [ ] keep storage/persistence abstract via small interfaces;
- [ ] keep rotation CAS/atomicity requirements explicit for stores;
- [ ] do not build DB/cache adapters into Epicrypt core;
- [ ] add concurrency/reuse/race tests at the contract boundary.

---

## 12. Secret/key generation and derivation

- [ ] consolidate `RandomBytesGenerator`, `NonceGenerator`, `SaltGenerator`, `TokenMaterialGenerator`, `KeyMaterialGenerator` and `MasterSecretGenerator` so each has a clear reason to exist and no overlapping encoding/length logic;
- [ ] centralize Base64URL/hex/raw output behavior;
- [ ] provide named generation profiles for master secrets, HMAC secrets, CSRF/signed-URL secrets, token ids and nonces where useful;
- [ ] use at least 256-bit entropy for general master/HMAC secrets unless a primitive requires another exact length;
- [ ] make key derivation HKDF/domain-separated and label-driven;
- [ ] prevent callers from accidentally reusing the same derived key across purposes;
- [ ] validate output lengths against hash/primitive limits;
- [ ] add RFC 5869 HKDF vectors;
- [ ] mark key/secret inputs sensitive consistently;
- [ ] use `sodium_memzero()` for mutable temporary secret/state buffers where practical, while documenting PHP copy-on-write/string limitations and never claiming guaranteed whole-process erasure.

---

## 13. Password subsystem

### Hashing

- [ ] keep Argon2id as the default and recommended new-write algorithm;
- [ ] consider removing Argon2i as a selectable **new-write** option in the 3.0 API while continuing to verify legacy Argon2i hashes through `password_verify()`;
- [ ] retain bcrypt only as an explicit compatibility/new-write option if required;
- [ ] keep strict bcrypt >72-byte rejection for new hashes and verification behavior documented;
- [ ] retain `password_needs_rehash()` semantics;
- [ ] expose recommended policy profiles only when backed by measured runtime budgets, not hard-coded marketing labels;
- [ ] test malformed/unsupported hashes without warnings.

### Peppering

- [ ] do **not** add implicit password peppering to `PasswordHasher` unless there is a clear storage/rotation model;
- [ ] if a pepper API is introduced, make it explicit, versioned/key-id aware and rotation-safe using KeyRing/derived keys;
- [ ] never silently change existing password hashes in a way applications cannot rotate.

### Compromised-password checking

Current package has a contract and null checker.

- [ ] consider an optional HIBP k-anonymity checker built only on the existing PSR HTTP boundary;
- [ ] never send raw password material;
- [ ] bound response size/time and validate response format;
- [ ] keep it optional and policy-driven so offline/password hashing does not require network access.

### Password policy/generation

- [ ] review entropy calculations and Unicode/byte semantics;
- [ ] distinguish password policy from passphrase generation;
- [ ] avoid composition rules that reduce usability without meaningful security benefit;
- [ ] keep generator CSPRNG-only and unbiased.

---

## 14. Data protection / envelope / wrapped secrets

- [ ] inventory every persisted/wire format version independently of package version;
- [ ] freeze deterministic 2.x test fixtures before refactoring;
- [ ] retain read/verify support for existing valid 2.x payloads;
- [ ] only bump format versions when cryptographic framing/security changes justify it;
- [ ] authenticate algorithm, purpose, key id, created-at and AAD metadata before releasing plaintext;
- [ ] reject unknown mandatory metadata rather than ignoring it;
- [ ] enforce payload/ciphertext/metadata size bounds;
- [ ] avoid attacker-controlled algorithm selection outside explicit allowlists;
- [ ] make fallback-key use observable in typed results so applications can re-protect/re-key;
- [ ] add `needsReprotect`/`usedFallbackKey`-style signals consistently where useful;
- [ ] add migration/re-protection helpers that transform old material without exposing plaintext longer than necessary;
- [ ] keep stable failure messages non-oracular;
- [ ] test truncation, corruption, metadata tampering, key mismatch, AAD mismatch and wrong-purpose behavior.

---

## 15. Primitive audit

Review every primitive class independently rather than assuming higher-level tests cover it.

### AEAD / secret box / public-key box

- [ ] verify nonce/key/tag lengths before native calls;
- [ ] avoid caller-supplied nonces unless the API makes misuse difficult and documents uniqueness requirements;
- [ ] keep AEGIS capability detection explicit and tested against modern libsodium;
- [ ] add authoritative libsodium vectors where available;
- [ ] normalize failure to Epicrypt exceptions.

### MAC/signature

- [ ] keep constant-time verification;
- [ ] validate minimum HMAC key lengths;
- [ ] prevent digest/algorithm downgrade through arbitrary strings;
- [ ] keep detached signature inputs clearly separated from encoded output.

### Ristretto / X25519 / Ed25519 / key exchange

- [ ] validate all-zero/invalid shared-secret cases;
- [ ] validate exact key lengths;
- [ ] preserve domain separation in derived session keys;
- [ ] benchmark phpseclib 4 vs native OpenSSL/libsodium only where both are realistic backends.

### Internal codecs

- [ ] eliminate duplicate Base64URL/JSON/binary-key validation implementations;
- [ ] reject non-canonical encodings where canonical form is security-relevant;
- [ ] bound JSON depth/size/count in security parsers;
- [ ] keep internal helpers internal unless there is a stable public use case.

---

## 16. Exception/result model and secret hygiene

- [ ] inventory exception hierarchy and remove ambiguous cross-domain exceptions;
- [ ] distinguish configuration/key-resolution/input-format/verification/backend-failure classes;
- [ ] expose stable non-sensitive public messages;
- [ ] preserve backend exception as `previous` only where useful for internal diagnostics;
- [ ] never interpolate private keys, passwords, tokens, plaintexts or raw secrets into exception messages;
- [ ] avoid including attacker-controlled full tokens/URLs where they may contain secrets;
- [ ] apply `#[SensitiveParameter]` consistently to secret/key/password/token/plaintext inputs;
- [ ] audit `__toString()`, `jsonSerialize()`, debug output and DTO public properties for accidental secret exposure;
- [ ] make result objects readonly/immutable where possible;
- [ ] prefer typed result enums/reasons over parsing exception strings;
- [ ] keep verification APIs available in both throwing and typed-result forms only where both have clear use cases; avoid redundant method explosion.

---

## 17. Bounds and denial-of-service policy

Create one documented security-limits layer rather than scattered magic constants.

At minimum define/test limits for:

- compact JWT/JWS/JWE total bytes;
- JOSE header bytes/member count/depth;
- claim JSON bytes/member count/depth;
- JWK field sizes and JWKS key count;
- remote discovery/JWKS bytes/depth/member count;
- signed payload bytes;
- signed URL query parameter count/name/value length;
- certificate/CSR/CRL/PFX/CMS bytes;
- certificate chain length;
- protected payload metadata and ciphertext;
- file header/framing size;
- stream chunk sizes;
- key ids/issuer/audience/purpose identifiers;
- password/passphrase input lengths where relevant.

- [ ] fail before expensive crypto whenever possible;
- [ ] make limits configurable only where applications reasonably need adjustment;
- [ ] do not allow a “0 = unlimited” security parser mode unless explicitly safe.

---

## 18. Signed URL review

`SignedUrl` is security-sensitive and currently implements its own strict parser/canonicalizer.

- [ ] preserve duplicate-query-key rejection and reserved-key protection;
- [ ] review array-parameter canonicalization for ambiguous PHP query forms;
- [ ] define percent-encoding/case/path normalization exactly and freeze vectors;
- [ ] verify host/scheme/default-port binding behavior;
- [ ] validate method binding and expiration boundary semantics;
- [ ] bound query pair count, key length, value length and total URL length;
- [ ] preserve versioned verification for existing signed URLs;
- [ ] allow key rotation through KeyRing rather than a single long-lived secret;
- [ ] report fallback-key use so applications can regenerate URLs where useful;
- [ ] do not make Epicrypt depend on Webrick/Foundation routing. Frameworks adapt their URLs into this lower-level boundary.

---

## 19. API/namespace cleanup for the major

Use the 3.0 major to improve coherence, but do not rename for aesthetics alone.

- [ ] review `Generate`, `Security`, `Token`, `DataProtection`, `Certificate`, `Integrity`, `Crypto` boundaries;
- [ ] eliminate duplicate `KeyPurpose` concepts if `Generate\KeyMaterial\Enum\KeyPurpose` and `Security\KeyPurpose` overlap semantically; use separate names only when they truly represent different domains;
- [ ] eliminate duplicate policy/codec helpers;
- [ ] standardize method vocabulary: `issue/verify`, `protect/unprotect`, `sign/verify`, `encrypt/decrypt`, `generate`, `derive`;
- [ ] prefer immutable configuration/result objects;
- [ ] avoid generic “Manager” classes where a more precise capability name exists;
- [ ] keep public constructors small and validate at construction time;
- [ ] no service locator/global registry/static mutable configuration;
- [ ] no framework/container coupling;
- [ ] write a complete 2.x → 3.0 migration table for renamed/removed classes and behavior changes.

---

## 20. Tests and security validation

Keep and extend the current PHPForge quality gates.

### Required matrices

- [ ] PHP 8.4 prefer-lowest;
- [ ] PHP 8.4 prefer-stable;
- [ ] PHP 8.5 prefer-lowest;
- [ ] PHP 8.5 prefer-stable;
- [ ] clean production install;
- [ ] **Epicrypt core without Pathwise installed**;
- [ ] Pathwise 4 dev/integration tests;
- [ ] phpseclib 4 native tests;
- [ ] OpenSSL capability matrix where behavior differs by linked OpenSSL version;
- [ ] modern libsodium/AEGIS positive environment;
- [ ] Windows where path/certificate behavior is supported and meaningful.

### Interoperability

Preserve the existing independent JOSE interoperability job and expand it where useful:

- [ ] JWS RSA/EC/EdDSA;
- [ ] RSA-PSS;
- [ ] JWE key-management/content-encryption algorithms;
- [ ] JWK/JWKS import/export;
- [ ] DPoP fixtures;
- [ ] X.509/CSR/PFX/CMS fixtures against OpenSSL/phpseclib/independent tooling as appropriate;
- [ ] existing Epicrypt 2.x protected/signed/wrapped fixture compatibility.

### Mutation/security-critical testing

Keep current mutation shards and add new/changed critical classes:

- [ ] stream `SecretStream`/`FileProtector` paths;
- [ ] phpseclib 4 key loaders/signature boundary;
- [ ] key-set readiness/rotation;
- [ ] remote JOSE DNS/redirect policy;
- [ ] certificate chain/PFX/CMS parsers;
- [ ] purpose-token replacement for Foundation HMAC codec.

### Fuzz/property/adversarial tests

- [ ] compact JOSE segment parser;
- [ ] JSON/JWK/JWKS validation;
- [ ] protected payload framing;
- [ ] signed URL parser/canonicalization;
- [ ] certificate/PEM/PFX inputs within bounded corpus sizes;
- [ ] truncation/corruption/bit-flip properties for authenticated formats;
- [ ] random interleaving of KeyRing active/fallback states;
- [ ] stream short-read/short-write/exception/early-abort behavior.

### Static/security gates

- [ ] PHPStan/Psalm clean;
- [ ] PHPForge architecture/lint/security/refactor gates clean;
- [ ] no skipped tests in release CI unless the job is explicitly a capability-negative matrix;
- [ ] composer audit clean;
- [ ] dependency license/security review;
- [ ] no sensitive values in snapshots/logs/fixtures.

---

## 21. Performance plan

Epicrypt 3 must preserve security first; performance decisions should be attributed to the correct layer.

### Baselines before implementation

Record 2.1/current-main baselines for:

1. symmetric AEAD encrypt/decrypt;
2. SecretStream local file throughput at multiple chunk sizes;
3. String/File/Envelope protection;
4. password hash/verify/rehash;
5. JWS/JWT sign/verify for HS/RS/PS/ES/EdDSA;
6. JWE encrypt/decrypt;
7. JWK/JWKS import/export/resolve;
8. Remote JWKS warm-cache resolution excluding network time;
9. key-ring active/fallback resolution;
10. certificate/key generation and parsing;
11. PKCS#12 import/export;
12. package autoload/clean-install memory footprint.

### 3.0 attribution

Add/compare:

- [ ] stream API vs existing Pathwise-backed file wrappers;
- [ ] local path wrapper overhead above stream core;
- [ ] phpseclib 4 vs current phpseclib 3 sign/verify/key-load costs;
- [ ] phpseclib 4 vs OpenSSL-native backend where both remain;
- [ ] PFX/CMS/X509 parse costs;
- [ ] key-ring lookup with realistic rotation sets;
- [ ] purpose-token issue/verify replacing Foundation HMAC codec;
- [ ] core install/boot/autoload without Pathwise;
- [ ] Pathwise 4 + Epicrypt integration overhead separately from crypto time.

Do not weaken validation or security limits to win microbenchmarks. Any backend fast path must have identical security semantics and cross-backend tests.

---

## 22. Documentation

Update/rewrite docs alongside implementation:

- [ ] architecture/ownership and dependency DAG;
- [ ] installation and optional integrations;
- [ ] Pathwise 4 stream integration example;
- [ ] phpseclib 4 migration notes;
- [ ] key generation/derivation/rotation guidance;
- [ ] purpose-token and signed-payload usage;
- [ ] JWT/JWS/JWE/JWK/JWKS security policy;
- [ ] DPoP and remote JWKS security/deployment guidance;
- [ ] certificate/CSR/chain/PFX/CMS usage;
- [ ] password policy and Argon2id guidance;
- [ ] persisted-format compatibility policy;
- [ ] exceptions and safe logging;
- [ ] performance/benchmark methodology;
- [ ] full Epicrypt 2.x → 3.0 migration guide.

Documentation must clearly distinguish:

- **package/API version**;
- **cryptographic wire/storage format version**;
- **algorithm/key rotation version**.

---

## 23. Foundation follow-up acceptance

Epicrypt 3 is not complete for the ecosystem until it can be consumed cleanly by Foundation.

After Epicrypt 3 reaches a release candidate:

- [ ] Foundation changes `infocyph/epicrypt` to `^3.0`;
- [ ] Foundation keeps `infocyph/pathwise ^4.0` independently;
- [ ] Composer resolves Epicrypt + Pathwise + OTP together without aliases/replaces/conflict hacks;
- [ ] Foundation Point 26.5 Pathwise 4 CI becomes installable and its existing Pathwise tests run;
- [ ] Foundation removes `Auth\Support\HmacTokenCodec`;
- [ ] Foundation removes/reduces parallel simple signed-token crypto mechanics;
- [ ] Foundation uses Epicrypt key derivation instead of raw application HMAC where the operation is generic crypto;
- [ ] Foundation OAuth signing-key resolver delegates key-pair/JWKS crypto readiness to Epicrypt;
- [ ] Foundation environment secret generation delegates secret material generation to Epicrypt;
- [ ] Foundation EnvironmentFileProtector remains only an application/path/config adapter over Epicrypt + storage mechanics;
- [ ] Foundation Epicrypt adapters are reduced to application contract/claim mappings rather than cryptographic implementations;
- [ ] OTP remains independently composable and no circular Composer dependency is introduced;
- [ ] Foundation full PHP 8.4/8.5 CI passes with Epicrypt 3 + Pathwise 4 + OTP current release.

---

## 24. Implementation sequence

Use this order to prevent dependency/API churn from invalidating later work.

### Phase A — freeze baselines and formats

1. [ ] capture current 2.x persisted-format fixtures and benchmark baselines — **partial:** durable string/file/signed-payload fixtures are frozen; numeric benchmark baselines remain open;
2. [x] enumerate public API slated for removal/rename — inventory added at `docs/plans/epicrypt-3-public-api-inventory.md`;
3. [x] document dependency/ownership decisions;
4. [x] add tests that prove current durable payload/file/token formats before refactoring.

### Phase B — break dependency coupling

5. [x] redesign `SecretStream`, `FileProtector`, `FileHasher` around streams;
6. [x] remove Pathwise imports from production source;
7. [x] move Pathwise to `require-dev ^4.0` only if integration tests still need it;
8. [ ] add no-Pathwise clean-install test — smoke script exists; dedicated `composer install --no-dev` CI gate still pending;
9. [x] add Pathwise 4 explicit-context stream interop test.

This phase alone should remove the Composer conflict that currently blocks Foundation 26.5.

### Phase C — phpseclib 4

10. [ ] raise phpseclib to native `^4.0.1` floor;
11. [ ] migrate namespaces/types/exceptions;
12. [ ] validate RSA/PS/EC/JWK/JWE paths;
13. [ ] run JOSE interoperability and benchmarks;
14. [ ] supersede PR #29.

### Phase D — key/token boundary consolidation

15. [ ] refine KeyRing/key readiness/key derivation;
16. [ ] add generic signing-key-set/keypair validation;
17. [ ] consolidate purpose/timed signed token API;
18. [ ] add Foundation replacement tests/fixtures for HmacTokenCodec/simple tokens;
19. [ ] improve signed URL KeyRing rotation support.

### Phase E — JOSE/network hardening

20. [ ] centralize JOSE limits/alg/key validation;
21. [ ] harden Remote JWKS DNS/redirect/network policy;
22. [ ] audit DPoP/OpenID validation;
23. [ ] expand adversarial/interoperability tests.

### Phase F — certificate/PKI modernization

24. [ ] migrate certificate loaders/model to phpseclib 4 where beneficial;
25. [ ] restructure CSR/chain validation;
26. [ ] implement/modernize CRL support if accepted;
27. [ ] migrate PKCS#12 to PFX model;
28. [ ] add CMS if it passes scope/security/interop review;
29. [ ] benchmark OpenSSL/phpseclib backend choices.

### Phase G — password/secret/data protection cleanup

30. [ ] finalize Argon2id/new-write policy;
31. [ ] consolidate secret/key generation APIs;
32. [ ] audit protected payload/envelope/wrapped-secret formats and migration signals;
33. [ ] finish exception/sensitive-parameter/zeroization pass.

### Phase H — release integration

34. [ ] run full PHPForge CI/mutation/interoperability matrix;
35. [ ] run performance attribution;
36. [ ] publish migration guide/docs;
37. [ ] create Epicrypt 3 RC;
38. [ ] integrate RC into Foundation and run full Foundation 3 gates;
39. [ ] resolve any ecosystem incompatibilities;
40. [ ] tag Epicrypt 3.0 only when Foundation + Pathwise 4 + OTP composition is green.

---

## 25. Explicit release gates

Epicrypt 3.0 cannot be marked complete until all of the following are true.

### Dependency gates

- [ ] no production dependency on Pathwise;
- [ ] no dependency on OTP;
- [ ] native phpseclib 4 requirement and implementation;
- [ ] clean Composer resolution alongside Pathwise 4 and OTP in Foundation;
- [ ] no compatibility aliases/replaces used to hide incompatible package metadata.

### Correctness/security gates

- [ ] existing durable 2.x artifacts remain readable/verifiable or have an explicit secured migration path;
- [ ] stream crypto handles short reads/writes/failures deterministically;
- [ ] output is not published after failed authentication/encryption/decryption;
- [ ] key rotation active/fallback behavior is deterministic;
- [ ] no private JWK/key material leaks through public export/results/errors;
- [ ] JOSE algorithm confusion is rejected;
- [ ] RSA-PSS/EC/EdDSA interoperability passes;
- [ ] remote JWKS SSRF/redirect/DNS policy is bounded;
- [ ] DPoP replay/binding policy passes adversarial tests;
- [ ] certificate/CSR/chain/PFX behavior passes independent fixtures;
- [ ] password hashing policy remains Argon2id-first and legacy verification works;
- [ ] sensitive parameters/errors/logging pass review;
- [ ] parser/input size/depth/count limits are enforced before expensive work.

### Runtime/isolation gates

- [ ] no global mutable key/storage/token registry;
- [ ] repeated/interleaved operations retain no prior secret/key/request state;
- [ ] Pathwise 4 integration uses explicit caller-owned contexts/streams only;
- [ ] parallel/Fiber tests for stateful-looking boundaries pass;
- [ ] all value/config objects intended for reuse are immutable or documented otherwise.

### QA gates

- [ ] PHP 8.4/8.5 prefer-lowest/stable green;
- [ ] clean production install green;
- [ ] no-Pathwise core install/test green;
- [ ] Pathwise 4 integration green;
- [ ] phpseclib 4 native matrix green;
- [ ] JOSE independent interoperability green;
- [ ] AEGIS positive capability job green;
- [ ] security-critical mutation threshold green;
- [ ] analyzers/security/audit clean;
- [ ] benchmarks recorded and no unexplained material regression.

### Ecosystem gates

- [ ] Foundation can raise Epicrypt to `^3.0` while retaining Pathwise `^4.0`;
- [ ] Foundation Point 26.5 can complete without dependency conflict;
- [ ] Foundation crypto duplication identified in this plan is removed/reduced;
- [ ] OTP remains independent and Foundation’s OTP/Epicrypt composition is green.

---

## 26. Non-goals for 3.0

To keep the major focused, do not add these unless implementation discovers a concrete requirement:

- no OTP algorithms or WebAuthn implementation in Epicrypt;
- no application OAuth authorization server;
- no database/cache/storage adapters in core;
- no cloud-vendor KMS/Vault SDK dependencies in core;
- no global service locator/key registry;
- no new PASETO/proprietary token family merely for feature count;
- no hidden AIA/CRL/OCSP network fetching;
- no broad CMS/SPKAC surface unless interoperability/security tests justify the feature;
- no phpseclib 3 compatibility shim;
- no Pathwise 3 compatibility layer;
- no wire-format v3 solely to match package version 3.

---

## 27. Final target

Epicrypt 3 should leave the ecosystem with a simpler and more durable boundary:

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

The 3.0 release is successful when Foundation no longer needs to maintain a second cryptographic token/key implementation and no package constraint prevents Epicrypt, OTP and Pathwise from being installed together.