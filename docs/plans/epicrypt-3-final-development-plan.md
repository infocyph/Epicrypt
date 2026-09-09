# Epicrypt 3.0 — Final Development and Release Plan

## Status

Target release: **Epicrypt 3.0**

Planning/release-candidate branch: `epicrypt-3/architecture-plan`

Baseline audited from `main`: `f80092978328cccaef0d2233b08ce95b453dd90a`.

Implementation status: **Phases A–G complete. Phase H release acceptance is active.**

Source/API backward compatibility is not a release constraint for this major. **Persisted cryptographic compatibility is a separate hard release constraint.** Existing valid Epicrypt 2.x encrypted, signed and protected-file artifacts remain readable/verifiable unless a concrete security reason requires retirement and an explicit migration path is supplied.

Release-candidate acceptance rule: the branch is not release-ready until the final exact branch head passes both Epicrypt acceptance workflows and the Foundation/Pathwise/OTP dependency composition is verified.

---

## Progress ledger

### Phase A — baseline, formats and API inventory — complete

Completed:

- froze durable Epicrypt 2.x compatibility fixtures for protected strings, protected files and signed-payload v2 tokens;
- captured baseline/current benchmark evidence before architectural changes;
- inventoried public surfaces and recorded every intentional 3.0 removal/contract change in `epicrypt-3-public-api-inventory.md`;
- separated package API compatibility from persisted-format compatibility;
- established the rule that package major version does not automatically create a new cryptographic wire format.

Result: the durable `ep2` string/file framing and signed-payload v2 formats remain supported by 3.0 compatibility tests.

### Phase B — stream-first crypto and Pathwise decoupling — complete

Completed:

- moved `SecretStream`, `FileProtector` and `FileHasher` to caller-owned native PHP stream cores;
- retained local-path convenience APIs;
- added bounded short-read/short-write handling;
- added shared input locking and atomic local output publication;
- added `ProtectionMetadata` for stream operations;
- removed every production Pathwise import;
- removed `infocyph/pathwise` from Composer `require`;
- retained Pathwise `^4.0` only in `require-dev` for explicit interoperability tests;
- added independent `StorageContext` Pathwise 4 stream-isolation coverage;
- added production `composer install --no-dev` / no-Pathwise smoke coverage;
- benchmarked stream-core versus local-wrapper overhead.

Final ownership rule:

- storage/application code resolves paths and opens remote/adapter streams;
- Epicrypt owns authenticated streaming crypto and local atomic crypto publication;
- caller-owned stream publication/rollback remains caller-owned;
- Epicrypt owns no storage registry, global mount or application path policy.

### Phase C — native phpseclib 4 — complete

Closed migration baseline: `d1bf66b2e3a9882a6f7bf8581586b833c0aeb362`.

Completed:

- raised phpseclib to `^4.0.1`;
- migrated natively to the `phpseclib4\` namespace;
- rejected a dual-major `^3 || ^4` compatibility shim;
- migrated JWT/JWS RSA-PSS, JWE RSA-OAEP-256, BigInteger/JWK/JWKS and encrypted-private-key paths;
- normalized backend exceptions into Epicrypt-owned error surfaces;
- prevented private-key/passphrase/backend details from leaking into public messages;
- superseded the old dependency-only phpseclib widening path;
- retained independent JOSE interoperability tests.

Public Epicrypt APIs expose no phpseclib implementation objects.

### Phase D — generic application crypto extraction — complete

Completed generic ownership intended for Foundation and other consumers:

- `PurposeToken` for purpose-bound timed signed tokens with `iat`, `exp`, optional `nbf`, generated token ID, optional subject, context binding and typed verification results;
- exact KeyRing active/fallback signing and verification with authenticated key IDs;
- public-safe key metadata;
- `KeyDeriver` for purpose-labelled/domain-separated application subkeys;
- `AsymmetricSigningKeySet` for signing-key readiness, pair coherence, algorithm/purpose/issuer eligibility and public-only JWKS export;
- `KeyPurpose::SIGNED_URL` and KeyRing-aware signed-URL rotation while preserving raw-secret v2 signed-URL format;
- `KeyMaterialEncoding::{BASE64URL,RAW,HEX}`;
- canonical `KeyMaterialGenerator::forMasterSecret()` and `forTokenSecret()`;
- removal of duplicate `Password\Secret\MasterSecretGenerator`;
- removal of duplicate `Generate\KeyMaterial\TokenMaterialGenerator`;
- generic random token/identifier text now uses `RandomBytesGenerator::string()`;
- cryptographic signing/MAC token secrets use `KeyMaterialGenerator::forTokenSecret()`;
- file/environment crypto publication ownership documented so applications do not implement a second crypto-adjacent staging protocol.

Foundation remains owner of `.env` file selection/editing/cache clearing, application config, application paths, CLI behavior and audit policy.

### Phase E — JOSE, OAuth, OpenID and remote key hardening — complete

Completed:

- strict JWT issuer/verifier algorithm and `typ` separation;
- curated HS/RS/PS/ES/EdDSA policies;
- RSA size and EC curve/algorithm checks;
- JWK/JWKS import/export validation and public/private/symmetric export separation;
- certificate-bound JWK/JWKS checks;
- compact, flattened and general JWS support;
- detached JWS and RFC 7797 `b64=false` critical-header handling;
- JWE with A256GCM content encryption and explicit supported key-management algorithms;
- nested JOSE support without header-driven algorithm selection;
- DPoP issue/verify/binding with atomic replay-store contract;
- OpenID ID-token nonce, authorized-party, auth-time and half-hash validation;
- Remote JWKS and OpenID discovery using explicit trusted configuration;
- no token-driven `jku`/`x5u` retrieval;
- bounded metadata/JWKS documents, cache lifetimes, stale use and unknown-`kid` forced refresh;
- explicit HTTP-client ownership of redirects, DNS/IP policy and network timeout behavior;
- durable opaque refresh-token lifecycle with atomic consume/replace, family reuse response, revocation and optional DPoP binding;
- shared-store requirements documented for replay/refresh state.

### Phase F — PKI modernization — complete

Completed:

- bounded backend-neutral `CertificateInspector` through phpseclib 4;
- bounded `CsrInspector` with CSR self-signature validation;
- explicit `CertificateChainVerifier` separating trust anchors from untrusted intermediates and certificate purpose;
- no hidden CA discovery, AIA fetching or mutable process-global trust registry;
- retained OpenSSL accelerated key generation and issuance APIs;
- retained `Pkcs12` as the public PFX/PKCS#12 boundary;
- phpseclib 4 performs bounded PFX parsing/model validation;
- OpenSSL performs interoperable PKCS#12 serialization;
- exported containers are reloaded/validated through phpseclib before publication;
- import requires a supported private key and matching certificate;
- private key is returned as normalized unencrypted PKCS#8 after successful password validation;
- bidirectional OpenSSL/phpseclib interoperability tests added;
- certificate/PKI mutation shard added;
- OpenSSL/phpseclib parsing and PFX benchmark attribution added.

Explicit 3.0 non-features:

- no first-class CRL verifier: the available convenience validation path would reintroduce shared/global issuer state; a future API must accept issuer/CRL explicitly and remain bounded/no-network;
- no CMS API: no current consumer justifies the parser/interoperability/misuse surface;
- no OCSP or AIA network fetching in core.

### Phase G — password, runtime bounds, secret hygiene and release hardening — complete

Completed:

- Argon2id is the sole modern password new-write profile;
- `PasswordHashAlgorithm::ARGON2I` is removed from the write API;
- existing Argon2i hashes remain verifiable by PHP and migrate to Argon2id via `verifyAndRehash()` after successful authentication;
- bcrypt remains explicit compatibility and rejects passwords over 72 bytes;
- password cost bounds remain explicit;
- sensitive-parameter coverage is audited across production call chains by reflection;
- safe logging/error guidance forbids plaintext, keys, passphrases, raw tokens/proofs, PKCS#12 blobs and complete attacker-controlled JOSE/protected values;
- protected metadata remains authenticated and key-rotation aware;
- compact protected values now fail oversized input before expensive parsing/crypto;
- `StringProtector` plaintext maximum: 16 MiB;
- encoded compact `ep2` maximum: 24 MiB;
- encoded protected header maximum: 32 KiB;
- `EnvelopeProtector` plaintext maximum: 8 MiB;
- larger content is directed to `FileProtector` streaming;
- benchmark class-order/style contract aligned with PHPForge;
- `PurposeToken` token IDs use the canonical `RandomBytesGenerator::string(48)` after removal of the duplicate token-material wrapper.

### Phase H — documentation, ecosystem acceptance and release — active

Completed documentation/repository work:

- README examples use `KeyMaterialEncoding` rather than removed boolean key-material encoding switches;
- token/security/generation/password/data-protection/PKI/error-handling docs match final 3.0 behavior;
- `migration-3.0.rst` documents dependency, API, password, format, size-bound, PKI and Foundation-oriented migration;
- migration guide linked from the documentation index;
- public API inventory finalized with no unresolved 3.0 release decision;
- PR #30 is the release-candidate integration PR.

Remaining acceptance gates before tag/publish:

- [ ] final exact-head `Epicrypt 3 Phase A+B Gates` workflow is green;
- [ ] final exact-head `Security & Standards` workflow is green across PHP 8.4/8.5, lowest/stable, static/security analysis, clean install, independent JOSE, AEGIS and all mutation shards;
- [ ] no actionable skipped/deprecated test remains under release policy;
- [ ] Foundation dependency composition is verified with Epicrypt 3 + OTP 6.x + Pathwise 4;
- [ ] Foundation application integration tests are green once its constraint points at a published Epicrypt 3 RC/stable version;
- [ ] PR #30 metadata is updated from historical phase notes to release-candidate scope.

---

## 1. Final ownership model

### Epicrypt owns

- cryptographic primitives and safe composition;
- secret/key generation and deterministic derivation;
- key identifiers, key rings, eligibility, rotation and signing readiness;
- versioned authenticated/encrypted/signed formats;
- purpose-bound timed-token mechanics;
- password hashing/verification/rehash/generation policy;
- JWT/JWS/JWE/JWK/JWKS, DPoP and OpenID cryptographic validation;
- opaque/refresh-token generic cryptographic lifecycle contracts;
- certificate/key/CSR/chain/PFX cryptographic operations;
- local/stream data-protection transforms and framing;
- integrity hashing/MAC/signature operations;
- strict crypto bounds, algorithm policy and stable result/exception types.

### Pathwise owns

- storage contexts/configuration/adapters;
- path routing and storage identity;
- adapter localization/staging/commit mechanics;
- generic filesystem IO, upload/download/archive/sync/retention policy.

Epicrypt has no production Pathwise dependency and no ambient Pathwise state.

### OTP owns

- OTP algorithms and provisioning;
- TOTP/HOTP/AOTP behavior;
- OTP replay/claim/consume semantics;
- OTP recovery-code semantics;
- passkey/WebAuthn ceremonies and MFA orchestration;
- OTP persistence/cache contracts.

Epicrypt does not depend on OTP in production.

### Foundation owns

- configuration/environment selection;
- DI/provider/runtime lifecycle;
- application paths and CLI;
- HTTP/router/session/auth/application OAuth orchestration;
- account/user/authorization behavior;
- database/cache repositories and transactions;
- application audit/diagnostics;
- selecting/configuring Epicrypt, OTP and Pathwise;
- adapting lower-level results into application/HTTP contracts.

Target dependency graph:

```text
Foundation
  ├── Epicrypt 3
  ├── OTP 6.x
  └── Pathwise 4

Epicrypt 3
  └── phpseclib 4

OTP 6.x
  └── no Epicrypt/Pathwise production dependency required

Pathwise 4
  └── no Epicrypt/OTP dependency
```

No aliases/replaces, Pathwise 3 bridge or runtime compatibility shim is allowed to solve ecosystem composition.

---

## 2. Composer/dependency release contract

Production:

- PHP `>=8.4`;
- `ext-hash`, `ext-json`, `ext-openssl`, `ext-sodium`;
- phpseclib `^4.0.1`;
- PSR clock/client/factory/simple-cache contracts as required;
- **no Pathwise**;
- **no OTP**.

Development:

- Pathwise `^4.0` for interoperability only;
- `infocyph/phpforge: dev-main@dev` remains the required project quality harness;
- HTTP mock/PSR-7 packages remain test-only where possible.

Release constraint guard must reject accidental unstable production constraints or reintroduction of Pathwise runtime coupling.

---

## 3. Persisted-format contract

Epicrypt cryptographic format versioning is independent of Composer/package major version.

Required for release:

- stable 2.x string fixture decrypts under 3.0;
- stable 2.x protected-file fixture decrypts under 3.0;
- stable signed-payload v2 fixture verifies under 3.0;
- format metadata remains authenticated;
- key IDs/purpose/AAD/domain/algorithm mismatches fail closed;
- unknown/missing KeyRing selectors do not trigger broad key scanning;
- no unplanned write-format migration is introduced.

A future format retirement requires security/interoperability rationale, old/new fixtures, explicit read/write policy and migration documentation.

---

## 4. Stream/local IO contract

Stream callers own stream lifetime and publication semantics. Epicrypt:

- reads/writes bounded chunks;
- detects no-progress reads before EOF;
- loops across short writes;
- validates final SecretStream tag/framing;
- does not close caller-owned streams;
- does not invent remote transaction semantics.

Local wrappers:

- require local paths;
- reject scheme/wrapper paths;
- reject same input/output where unsafe;
- use shared input locks;
- stage sibling output with restrictive permissions;
- flush and atomically publish only complete authenticated operations;
- preserve an existing destination on failed operation;
- remove uncommitted staging artifacts.

---

## 5. Key material and rotation contract

- explicit `KeyMaterialEncoding` only;
- lengths mean raw entropy bytes before encoding;
- Base64URL default for config/secret-manager material;
- RAW for binary crypto APIs;
- HEX where configuration requires text hex;
- `KeyRing` requires explicit status/purpose/algorithm eligibility;
- exactly one eligible active write key;
- fallback keys are read-only;
- retired/disabled keys are ineligible;
- signed key selectors are authenticated before trust;
- generic key metadata never exposes secret bytes;
- derivation context/labels/subkey IDs are long-lived data contracts.

---

## 6. Password contract

- default/new write: Argon2id;
- Argon2i: legacy verification/rehash only, no new-write enum;
- bcrypt: explicit compatibility only;
- bcrypt inputs over 72 bytes rejected;
- Argon2 costs bounded;
- login migration occurs only after successful password verification;
- passwords are never encrypted or hashed with general-purpose fast digests.

---

## 7. JOSE/OAuth/OpenID contract

- algorithm/type policy fixed by trusted verifier configuration;
- untrusted JOSE headers never choose crypto policy or remote destinations;
- unknown critical headers fail;
- JWK key type/curve/RSA size/metadata/algorithm must agree;
- public JWKS never includes private/symmetric material;
- secret JWK export is explicitly named;
- DPoP/replay state requires shared atomic storage;
- refresh-token store must atomically consume/replace and retain reuse evidence through grant lifetime;
- raw refresh tokens are never persisted;
- Remote JWKS/OIDC retrieval accepts only trusted configured origins/allowed hosts with bounded documents/cache/stale behavior;
- redirect/DNS/IP/network timeout enforcement belongs to the HTTP client boundary.

---

## 8. PKI contract

- phpseclib 4: bounded parser/model boundary;
- OpenSSL: accelerated key generation/issuance/chain verification and interoperable PKCS#12 serialization;
- no backend implementation object in public Epicrypt contracts;
- trust anchors supplied explicitly;
- intermediates untrusted and supplied explicitly;
- no hidden CA/AIA/OCSP network discovery;
- chain verification is distinct from hostname verification;
- PFX import/export bounded and key/certificate coherence checked;
- CRL/CMS remain explicit non-goals for 3.0 as documented.

---

## 9. Exception/result and secret-hygiene contract

- expected protocol outcomes may use typed result objects;
- configuration/programmer errors throw stable Epicrypt exceptions;
- backend exceptions may be retained as `previous` for operator debugging but public messages remain non-sensitive;
- `#[SensitiveParameter]` used across secret-bearing production call chains and audited by reflection;
- no key/plaintext/password/passphrase/raw-token/proof/container leakage through messages or recommended logging;
- deterministic auth/configuration failures are not retried as transient operations.

---

## 10. Bounds and DoS contract

All attacker-controlled parsing/crypto surfaces require explicit practical bounds before expensive work where possible, including:

- compact protected values and metadata;
- file crypto chunks/frame lengths;
- JOSE compact/JSON structures;
- JWK/JWKS document/key counts and key sizes;
- Remote OpenID/JWKS documents;
- PKI/CSR/certificate/PFX inputs and chain counts;
- password costs and token TTLs;
- identifier/purpose/context/AAD lengths;
- refresh/replay state transitions.

Large arbitrary content belongs on streaming APIs rather than raising in-memory limits.

---

## 11. Performance contract

Benchmarks are attribution tools, not permission to weaken validation.

Required benchmark areas:

- stream core versus local wrapper;
- primitive encrypt/decrypt/sign/verify/hash;
- JOSE issue/verify/encrypt/decrypt;
- Remote JOSE hot-cache behavior where deterministic;
- password hashing/verification attribution;
- certificate parsing/key generation/PFX import;
- generation/derivation helpers.

Security, compatibility, bounds and correctness take precedence over microbenchmark gains.

---

## 12. Documentation contract

Release documentation must contain:

- installation/runtime requirements;
- migration from 2.x;
- persisted-format compatibility statement;
- stream ownership/publication model;
- data-protection size limits;
- key encoding and derivation semantics;
- Argon2id/legacy password migration policy;
- JOSE/OAuth/DPoP/Remote JWKS security boundaries;
- PKI backend split and explicit CRL/CMS non-goals;
- safe logging/error guidance;
- complete examples using only 3.0 public APIs.

No documentation example may use a removed 3.0 API.

---

## 13. Test/security release matrix

Required exact-head gates:

- Composer validation and stable runtime-constraint guard;
- PHP 8.4 and PHP 8.5;
- prefer-lowest and prefer-stable;
- Pest full suite with release skip/deprecation policy;
- Pint, PHPCS, PHPProbe, Deptrac, Rector and Composer Normalize;
- PHPStan and Psalm security analysis;
- Composer audit;
- production clean install/no-dev smoke;
- no-Pathwise runtime boundary test;
- Pathwise 4 explicit-context interop;
- independent JOSE interoperability;
- AEGIS/libsodium compatibility job;
- mutation shards for data protection, JWE, JWS, validation policy, JWT policy, refresh token, signed helpers, primitive verification, Remote JOSE and certificate/PKI;
- frozen 2.x persisted compatibility fixtures;
- adversarial malformed/tampered/boundary tests.

Any red exact-head lane blocks release.

---

## 14. Foundation acceptance

Foundation integration should replace application-local generic crypto mechanics, not application ownership:

Move/use Epicrypt for:

- generic signed/timed HMAC token mechanics -> `PurposeToken`;
- application cryptographic subkey derivation -> `KeyDeriver`;
- canonical deployment secret generation -> `KeyMaterialGenerator`;
- asymmetric signing-key readiness/JWKS coherence -> `AsymmetricSigningKeySet` + JOSE primitives;
- file crypto over application-owned storage streams -> `FileProtector`.

Keep in Foundation:

- environment-file selection/editing/cache clearing;
- application paths/config/CLI;
- HTTP/OAuth server routes, grants and consent;
- persistence/repositories/transactions;
- application session/cookie/rate-limit/audit behavior;
- WebAuthn/OTP domain orchestration.

Foundation release acceptance requires the real dependency graph to resolve with Epicrypt 3 + OTP 6.x + Pathwise 4 and its PHP 8.4/8.5 CI to pass after the Epicrypt 3 RC/stable constraint is consumable.

---

## 15. Release sequence

1. [x] freeze 2.x durable-format fixtures and baseline evidence;
2. [x] decouple Pathwise and ship stream-native file/integrity core;
3. [x] migrate to native phpseclib 4.0.1+;
4. [x] extract generic purpose-token/key/signing/readiness/generation surfaces;
5. [x] harden JOSE, DPoP, Remote JWKS/OpenID and refresh lifecycle;
6. [x] modernize PKI and close CRL/CMS decisions;
7. [x] finalize password/runtime/secret-hygiene/bounds policy;
8. [x] finalize 3.0 migration docs and API inventory;
9. [ ] pass final exact-head Epicrypt workflows;
10. [ ] verify Foundation ecosystem dependency composition;
11. [ ] update PR #30 as non-draft release candidate;
12. [ ] after a consumable RC/stable version exists, run Foundation PHP 8.4/8.5 integration and close its Point 26.5;
13. [ ] tag/publish Epicrypt 3.0 only after all release gates are green.

---

## 16. Explicit 3.0 non-goals

- no Pathwise production dependency or storage registry;
- no OTP production dependency;
- no application/framework configuration ownership;
- no hidden filesystem/network/global trust state;
- no generic broker/cache/database implementation inside Epicrypt;
- no token-header-driven remote key retrieval;
- no compression or legacy RSA1_5 JWE;
- no first-class CRL, OCSP, AIA-fetching or CMS surface without a concrete bounded explicit-state consumer design;
- no wire-format bump solely because the Composer major is 3;
- no security validation removal justified only by benchmark cost.

---

## 17. Final target

Epicrypt 3.0 should release as a storage-independent, stream-first, phpseclib-4-native security library with:

- preserved valid 2.x durable formats;
- explicit modern key/password/algorithm policy;
- no ambient/global storage or trust state;
- bounded attacker-controlled parsing and cryptographic work;
- stable typed result/exception surfaces;
- safe key rotation/readiness and purpose separation;
- strict JOSE/OAuth/OpenID/Remote JWKS behavior;
- interoperable PKI/PFX tooling;
- comprehensive PHPForge/static/security/mutation/interoperability gates;
- a dependency graph that composes cleanly with Foundation, OTP and Pathwise 4.

The release is complete only when the final exact branch head is green and Foundation can consume the published Epicrypt 3 line without reintroducing the old Pathwise 3 conflict.
