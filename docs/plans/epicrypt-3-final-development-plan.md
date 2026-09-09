# Epicrypt 3.0 — Final Development and Release Plan

## Final status

Target release: **Epicrypt 3.0**

Release-candidate branch: `epicrypt-3/architecture-plan`

Audited baseline: `f80092978328cccaef0d2233b08ce95b453dd90a` (`main` when the 3.0 work started).

Implementation status: **Phases A–H complete. Epicrypt 3.0 is release-ready pending the deliberate maintainer actions to merge/tag/publish.**

Release-ready implementation head: `dd6beb75eeefc11cd253862105660d89b6fda441`.

Acceptance evidence on that head:

- **Epicrypt 3 Phase A+B Gates #172** — run `34317347038` — **green**;
- **Security & Standards #220** — run `34317347426` — **green**;
- Foundation + Epicrypt 3 + OTP 6.1 + Pathwise 4 Composer composition — **green on PHP 8.4 and PHP 8.5** inside A+B #172;
- PR #30 is titled **Epicrypt 3.0 release candidate**, has release-candidate scope/documentation, is open, mergeable, and **ready for review**.

The final ledger/status commit after `dd6beb75` changes documentation only. It must remain green under the same PR checks before a maintainer tags/publishes the release; no additional runtime implementation work is planned.

Source/API backward compatibility is intentionally not a constraint for this major. **Persisted cryptographic compatibility is a separate hard release constraint.** Valid Epicrypt 2.x encrypted/signed/protected-file artifacts remain readable/verifiable unless a future release has a concrete security reason, frozen migration fixtures and an explicit migration path.

---

## Phase ledger

### Phase A — baseline, durable formats and API inventory — complete

- [x] freeze stable Epicrypt 2.x string-protection fixture;
- [x] freeze stable Epicrypt 2.x protected-file fixture;
- [x] freeze stable signed-payload v2 fixture;
- [x] capture comparable baseline/current benchmark evidence;
- [x] inventory public surfaces and record intentional 3.0 removals/changes;
- [x] separate package API compatibility from persisted cryptographic compatibility;
- [x] reject package-major-driven wire-format bumps.

Result: 3.0 continues to read/verify the valid frozen 2.x formats.

### Phase B — stream-first file/integrity core and Pathwise decoupling — complete

- [x] make native caller-owned PHP streams the core of `SecretStream`;
- [x] make native caller-owned PHP streams the core of `FileProtector`;
- [x] add stream-native `FileHasher`;
- [x] retain local-path convenience APIs;
- [x] add bounded short-read/short-write handling;
- [x] add shared input locking and atomic local output publication;
- [x] add metadata-only `ProtectionMetadata` for stream operations;
- [x] remove every production Pathwise import;
- [x] remove `infocyph/pathwise` from production Composer `require`;
- [x] retain Pathwise `^4.0` only in `require-dev` for interoperability;
- [x] test independent Pathwise 4 `StorageContext` stream isolation;
- [x] add `composer install --no-dev` / no-Pathwise production smoke gate;
- [x] benchmark stream core versus local wrappers.

Final ownership: storage/application code resolves remote/adapter paths and owns stream publication semantics; Epicrypt owns authenticated stream crypto and the single local atomic crypto-publication layer. Epicrypt owns no storage registry, global mount or application path policy.

### Phase C — native phpseclib 4 — complete

- [x] require `phpseclib/phpseclib ^4.0.1`;
- [x] migrate natively to phpseclib 4 namespaces/APIs;
- [x] reject a `^3 || ^4` shim and runtime namespace probing;
- [x] migrate JWT/JWS RSA-PSS support;
- [x] migrate JWE RSA-OAEP-256 support;
- [x] migrate BigInteger/JWK/JWKS operations;
- [x] migrate encrypted private-key/JWK paths;
- [x] normalize backend failures into Epicrypt-owned exceptions/results;
- [x] prevent backend key/passphrase detail leakage;
- [x] keep independent JOSE interoperability coverage;
- [x] expose no phpseclib implementation object through public Epicrypt contracts.

### Phase D — generic application crypto/key lifecycle — complete

- [x] add generic purpose-bound timed `PurposeToken` mechanics;
- [x] support `iat`, `exp`, optional `nbf`, generated token IDs, purpose/context/subject binding and caller claims;
- [x] add typed token verification failure/results;
- [x] add exact KeyRing active/fallback signing and verification with authenticated key IDs;
- [x] add public-safe key metadata;
- [x] add purpose/domain-separated `KeyDeriver` application subkeys;
- [x] add `AsymmetricSigningKeySet` readiness, pair coherence and public-only JWKS export;
- [x] add dedicated `KeyPurpose::SIGNED_URL`;
- [x] add authenticated KeyRing signed-URL rotation while preserving raw-secret v2 signed URLs;
- [x] add `KeyMaterialEncoding::{BASE64URL,RAW,HEX}`;
- [x] make `KeyMaterialGenerator` the canonical master/application/token-secret generator;
- [x] add `forTokenSecret()`;
- [x] remove duplicate `Password\Secret\MasterSecretGenerator`;
- [x] remove duplicate `Generate\KeyMaterial\TokenMaterialGenerator`;
- [x] use `RandomBytesGenerator::string()` for generic opaque/random token material;
- [x] use `KeyMaterialGenerator::forTokenSecret()` for cryptographic signing/MAC token secrets;
- [x] keep environment-file selection/editing/config/CLI ownership in Foundation.

### Phase E — JOSE, OAuth, OpenID and remote-key hardening — complete

- [x] strict JWT issuer/verifier algorithm and `typ` separation;
- [x] curated HS/RS/PS/ES/EdDSA policy;
- [x] RSA-size and EC-curve/algorithm validation;
- [x] validated JWK/JWKS public/private/symmetric export boundaries;
- [x] certificate-bound JWK/JWKS validation;
- [x] compact/flattened/general JWS;
- [x] detached JWS and RFC 7797 `b64=false` critical-header behavior;
- [x] JWE A256GCM content encryption with curated key-management algorithms;
- [x] nested JOSE without untrusted-header algorithm selection;
- [x] DPoP issue/verify/binding and atomic replay-store contract;
- [x] OpenID nonce, authorized-party, authentication-age and half-hash validation;
- [x] Remote JWKS/OpenID discovery from trusted configuration only;
- [x] reject token-driven `jku`/`x5u` retrieval;
- [x] bound remote documents, cache lifetimes, stale use and unknown-`kid` refresh;
- [x] keep redirect/DNS/IP/network-timeout policy at the supplied HTTP-client boundary;
- [x] durable opaque refresh-token rotation/reuse/revocation contract;
- [x] require atomic shared stores for refresh/replay state.

### Phase F — PKI modernization — complete

- [x] bounded backend-neutral `CertificateInspector` via phpseclib 4;
- [x] bounded `CsrInspector` with CSR self-signature validation;
- [x] explicit `CertificateChainVerifier` with caller-supplied trust anchors/intermediates/purpose;
- [x] no hidden CA discovery, AIA fetching or mutable process-global trust registry;
- [x] retain OpenSSL accelerated key generation and issuance;
- [x] retain `Pkcs12` as the public PFX/PKCS#12 boundary;
- [x] use phpseclib 4 for bounded PFX parsing/model validation;
- [x] use OpenSSL for interoperable PKCS#12 serialization;
- [x] validate exported PFX through phpseclib before publication;
- [x] require matching supported private key + certificate on import;
- [x] normalize imported private key to unencrypted PKCS#8 after successful password validation;
- [x] add bidirectional OpenSSL/phpseclib interoperability coverage;
- [x] add certificate/PKI mutation coverage;
- [x] benchmark OpenSSL/phpseclib parsing/key-generation/PFX paths;
- [x] explicitly defer CRL verification until an explicit-state, bounded, no-hidden-network design exists;
- [x] explicitly exclude CMS from 3.0 until a concrete consumer justifies its surface;
- [x] keep OCSP/AIA network retrieval outside core.

### Phase G — password, bounds, secret hygiene and hardening — complete

- [x] make Argon2id the sole modern new-write password profile;
- [x] remove `PasswordHashAlgorithm::ARGON2I` from the write API;
- [x] preserve existing Argon2i verification through PHP and migrate on successful `verifyAndRehash()`;
- [x] retain bcrypt only as explicit compatibility and enforce its 72-byte input limit;
- [x] retain explicit Argon2/bcrypt cost bounds;
- [x] reflection-audit secret-bearing production call chains for `#[SensitiveParameter]`;
- [x] document safe logging/error-chain behavior;
- [x] authenticate protected metadata and KeyRing selectors;
- [x] bound compact protected input before expensive parse/crypto work;
- [x] cap `StringProtector` plaintext at 16 MiB;
- [x] cap encoded compact `ep2` at 24 MiB;
- [x] cap encoded protected metadata header at 32 KiB;
- [x] cap `EnvelopeProtector` plaintext at 8 MiB;
- [x] direct larger arbitrary content to `FileProtector` streams;
- [x] align benchmark source with PHPForge/Pint class-element ordering;
- [x] preserve `PurposeToken` 48-character token IDs using canonical `RandomBytesGenerator::string(48)`.

### Phase H — documentation, ecosystem acceptance and release readiness — complete

- [x] README uses only final 3.0 key-material APIs;
- [x] generation/password/data-protection/security/token/JOSE/PKI/error docs match final behavior;
- [x] add `docs/migration-3.0.rst`;
- [x] link migration guide from documentation index;
- [x] finalize public API inventory with no unresolved 3.0 release decision;
- [x] update PR #30 to release-candidate scope;
- [x] mark PR #30 ready for review;
- [x] production no-Pathwise install gate green;
- [x] Pathwise 4 explicit-context stream interop green;
- [x] Foundation + Epicrypt 3 + OTP 6.1 + Pathwise 4 dependency composition green on PHP 8.4;
- [x] Foundation + Epicrypt 3 + OTP 6.1 + Pathwise 4 dependency composition green on PHP 8.5;
- [x] PHP 8.4/8.5 prefer-lowest/prefer-stable QA green;
- [x] PHPStan/Psalm/security analysis green;
- [x] clean production install green;
- [x] independent JOSE interoperability green;
- [x] AEGIS/libsodium compatibility green;
- [x] all security-critical mutation shards green, including data protection, JWE, JWS, validation policy, JWT policy, refresh token, signed helpers, primitive verification, Remote JOSE and certificate/PKI;
- [x] Pest release policy runs with `fail_on_skipped_tests=true` and no actionable skipped/deprecated test remains;
- [x] release-ready implementation head `dd6beb75` accepted by A+B #172 and Security #220.

Downstream note: after a 3.x RC/stable version is published, Foundation should replace its temporary `^2.1` dev constraint with the consumable 3.x line and run its own application-level PHP 8.4/8.5 CI. That is a **Foundation integration/release task**, not remaining Epicrypt 3 implementation work. The Composer blocker itself is already proven closed by Epicrypt's permanent ecosystem composition gate.

---

## Final ownership model

### Epicrypt owns

- cryptographic primitives and safe composition;
- secret/key generation and deterministic derivation;
- key IDs, KeyRing eligibility/rotation/readiness;
- authenticated/encrypted/signed format rules;
- generic purpose-bound timed-token mechanics;
- password hashing/verification/rehash policy;
- JWT/JWS/JWE/JWK/JWKS, DPoP and OpenID cryptographic validation;
- generic opaque/refresh-token cryptographic lifecycle contracts;
- certificate/key/CSR/chain/PFX cryptographic operations;
- local/stream data-protection transformations and framing;
- integrity hashing/MAC/signature operations;
- strict crypto bounds, algorithm policy and stable result/exception types.

### Pathwise owns

- storage contexts/configuration/adapters;
- path routing/storage identity;
- adapter localization/staging/commit mechanics;
- generic filesystem IO, upload/download/archive/sync/retention policy.

Epicrypt has no production Pathwise dependency and no ambient Pathwise state.

### OTP owns

- OTP algorithms/provisioning;
- TOTP/HOTP/AOTP semantics;
- OTP replay/claim/consume behavior;
- OTP-specific recovery codes;
- passkey/WebAuthn ceremonies and MFA orchestration;
- OTP persistence/cache contracts.

Epicrypt has no OTP production dependency.

### Foundation owns

- application config/environment selection;
- DI/provider/runtime lifecycle;
- application paths and CLI;
- HTTP/router/session/auth/application OAuth orchestration;
- account/user/authorization behavior;
- database/cache repositories and transactions;
- application audit/diagnostics;
- selecting/configuring Epicrypt, OTP and Pathwise;
- adapting lower-layer results into application/HTTP contracts.

Target graph:

```text
Foundation
  ├── Epicrypt 3
  ├── OTP 6.x
  └── Pathwise 4

Epicrypt 3
  └── phpseclib 4

OTP 6.x
  └── no Epicrypt/Pathwise production edge

Pathwise 4
  └── no Epicrypt/OTP production edge
```

No aliases/replaces, Pathwise 3 bridge or runtime compatibility shim is used.

---

## Release contracts

### Composer/runtime

Production:

- PHP `>=8.4`;
- `ext-hash`, `ext-json`, `ext-openssl`, `ext-sodium`;
- phpseclib `^4.0.1`;
- required PSR clock/HTTP/cache interfaces;
- **no Pathwise**;
- **no OTP**.

Development keeps Pathwise `^4.0` for interoperability and `infocyph/phpforge: dev-main@dev` as the quality/security harness.

### Persisted formats

Cryptographic format versioning is independent from Composer/package major version.

Release invariants:

- frozen 2.x string fixture decrypts under 3.0;
- frozen 2.x protected-file fixture decrypts under 3.0;
- frozen signed-payload v2 fixture verifies under 3.0;
- domain/purpose/AAD/algorithm/key-ID metadata remains authenticated;
- missing/unknown KeyRing selectors fail closed instead of scanning keys;
- no unplanned 3.0 write-format migration exists.

### Stream/local IO

Caller-owned streams:

- bounded reads/writes;
- no-progress detection;
- short-write loops;
- final SecretStream framing/tag validation;
- no caller-stream closing;
- no invented remote transaction/publication semantics.

Local-path wrappers:

- local filesystem paths only;
- same-path/scheme misuse rejected;
- shared input locks;
- restrictive sibling staging;
- flush + atomic publish only after complete success;
- preserve existing destination on failure;
- clean staging artifacts.

### Key/password policy

- explicit `KeyMaterialEncoding` only;
- lengths represent raw entropy bytes before encoding;
- KeyRing write/read eligibility is purpose/algorithm/status bound;
- exactly one eligible active write key;
- fallback keys are read-only;
- disabled/retired keys are ineligible;
- derivation contexts/labels/subkey IDs are durable data contracts;
- Argon2id is the default/new-write password algorithm;
- Argon2i is legacy verification/rehash only;
- bcrypt is explicit compatibility only.

### JOSE/OAuth/OpenID

- trusted configuration fixes algorithms/types;
- untrusted headers never choose verification policy or remote destinations;
- unknown critical headers fail;
- JWK type/curve/RSA-size/metadata/algorithm must agree;
- public JWKS contains no private/symmetric material;
- DPoP and replay state require atomic shared storage;
- refresh-token consume/replace/reuse handling requires atomic durable storage;
- raw refresh tokens are never persisted;
- Remote JWKS/OpenID origins/hosts/documents/cache/stale behavior are bounded and explicit;
- HTTP redirect/DNS/IP/network-timeout enforcement stays at the supplied HTTP-client boundary.

### PKI

- phpseclib 4 is the bounded parser/model boundary;
- OpenSSL remains the accelerated key-generation/issuance/chain-verification/interoperable-PKCS12 backend;
- no backend implementation object leaks into public contracts;
- trust anchors/intermediates supplied explicitly;
- no hidden CA/AIA/OCSP discovery;
- chain verification is distinct from hostname verification;
- PFX import/export is bounded and key/certificate coherence checked;
- CRL/CMS/OCSP/AIA-fetching are explicit 3.0 non-features as documented.

### Errors, secrets and bounds

- expected protocol outcomes may use typed result objects;
- configuration/programmer failures use stable Epicrypt exceptions;
- backend exceptions may be retained as `previous` but public messages remain non-sensitive;
- no plaintext/key/password/passphrase/raw-token/proof/container leakage is recommended or tested;
- attacker-controlled parsing/crypto work is explicitly bounded before expensive work where practical;
- large arbitrary content uses streaming APIs rather than increased in-memory limits.

---

## Release acceptance evidence

### A+B #172 — `34317347038` — green on `dd6beb75`

Passed:

- production install without Pathwise;
- Pathwise 4 explicit-context stream interoperability;
- frozen Epicrypt 2.1 baseline/current benchmark evidence;
- **Foundation + Epicrypt 3 + OTP 6.1 + Pathwise 4 Composer resolution on PHP 8.4**;
- **Foundation + Epicrypt 3 + OTP 6.1 + Pathwise 4 Composer resolution on PHP 8.5**;
- explicit rejection of a resolved Pathwise 3 edge.

The Foundation gate uses the real `foundation-3/close-26.6` branch, changes only its temporary CI copy from Epicrypt `^2.1` to `^3.0`, injects the current Epicrypt checkout as version `3.0.0`, and resolves the complete Foundation development dependency graph. No Foundation repository state is changed by this proof.

### Security & Standards #220 — `34317347426` — green on `dd6beb75`

Passed:

- PHP 8.4 prefer-lowest QA;
- PHP 8.4 prefer-stable QA;
- PHP 8.5 prefer-lowest QA;
- PHP 8.5 prefer-stable QA;
- PHP 8.4 analysis;
- PHP 8.5 analysis;
- Composer stable-runtime constraint guard;
- Pest;
- Pint;
- PHPCS;
- PHPProbe;
- Deptrac;
- Rector;
- Composer Normalize;
- PHPStan/Psalm/security analysis;
- clean `--no-dev` production install;
- independent JOSE interoperability;
- AEGIS on libsodium 1.0.22;
- mutation: data protection;
- mutation: JWE;
- mutation: JWS;
- mutation: validation policy;
- mutation: JWT policy;
- mutation: refresh token;
- mutation: signed helpers;
- mutation: primitive verification;
- mutation: Remote JOSE;
- mutation: certificate/PKI.

Optional reusable-workflow report/benchmark jobs that were not configured are not skipped tests. The test workflow itself uses the release `fail_on_skipped_tests=true` policy.

---

## Documentation/release artifacts

- [x] README finalized;
- [x] Sphinx documentation index finalized;
- [x] migration guide: `docs/migration-3.0.rst`;
- [x] public API inventory: `docs/plans/epicrypt-3-public-api-inventory.md`;
- [x] stream/data-protection documentation;
- [x] generation/key-derivation documentation;
- [x] password migration documentation;
- [x] JOSE/OAuth/OpenID/Remote JWKS documentation;
- [x] PKI backend/non-goal documentation;
- [x] safe logging/error documentation;
- [x] PR #30 release-candidate description;
- [x] PR #30 ready-for-review transition.

No documentation example intentionally references a removed 3.0 public API.

---

## Explicit 3.0 non-goals

- no production Pathwise dependency or storage registry;
- no production OTP dependency;
- no application/framework configuration ownership;
- no hidden filesystem/network/global trust state;
- no broker/cache/database implementation inside Epicrypt;
- no token-header-driven remote key retrieval;
- no JWE compression or RSA1_5;
- no first-class CRL/OCSP/AIA-fetching/CMS API without a concrete bounded explicit-state design;
- no package-major-only cryptographic wire-format bump;
- no removal of security validation solely for benchmark performance.

---

## Release sequence

- [x] implement Epicrypt 3 architecture and security work;
- [x] preserve durable 2.x compatibility fixtures;
- [x] decouple Pathwise production dependency;
- [x] migrate to native phpseclib 4.0.1+;
- [x] finalize application-crypto/key-generation surfaces;
- [x] finalize JOSE/OAuth/OpenID/Remote JWKS behavior;
- [x] finalize PKI decisions and interoperability;
- [x] finalize password/runtime/bounds/secret-hygiene policy;
- [x] finalize migration docs and API inventory;
- [x] pass release-ready implementation exact-head A+B workflow;
- [x] pass release-ready implementation exact-head Security & Standards workflow;
- [x] prove Foundation + Epicrypt 3 + OTP 6.1 + Pathwise 4 dependency composition on PHP 8.4/8.5;
- [x] update PR #30 and mark it ready for review;
- [ ] **maintainer release action:** merge/tag/publish Epicrypt 3.0 (intentionally not performed as part of implementation readiness);
- [ ] **downstream Foundation action after a consumable 3.x version exists:** change Foundation's Epicrypt constraint and run its application-level CI.

The two remaining unchecked items are release/dependent-project actions, not unfinished Epicrypt 3 implementation.

---

## Final target achieved

Epicrypt 3.0 is prepared as a storage-independent, stream-first, phpseclib-4-native security library with preserved valid 2.x durable formats, explicit modern key/password policy, no ambient storage/trust state, bounded attacker-controlled work, safe rotation/readiness, strict JOSE/OAuth/OpenID/Remote JWKS behavior, interoperable PKI/PFX tooling, comprehensive PHPForge/static/security/mutation/interoperability gates, and a dependency graph proven to compose with Foundation, OTP 6.1 and Pathwise 4.

No code/API task remains before a maintainer chooses to merge/tag/publish the 3.0 release candidate, provided the final documentation-only ledger commit remains green under the same PR checks.
