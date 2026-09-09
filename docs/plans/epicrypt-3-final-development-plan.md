# Epicrypt 3 — Final Authentication Protocol Development Plan

**Status:** Active implementation plan  
**Target:** Epicrypt 3.0  
**Branch:** `epicrypt-3/architecture-plan`  
**Regression baseline:** `cca7e5a93f8b5f37329053b448fbce91e9496262`  
**Auth scope-extension baseline:** `0ec8744232f1c67f776a8fbd5414eee7a01369ab`  
**Priority:** standards correctness → security → deterministic state semantics → framework neutrality → performance → ergonomics

> Epicrypt 3.0 is still under development and has not been released. Until the 3.0 public release is cut, **source/API backward compatibility is not a design constraint**. Prefer the clean final 3.0 API and remove superseded unreleased surfaces instead of carrying compatibility wrappers or parallel implementations.
>
> Persisted cryptographic compatibility is a separate concern. Frozen Epicrypt 2.x `ep2` string/file formats and signed-payload v2 fixtures remain supported where the existing 3.0 plan already established them as durable format contracts. Package API freedom does not implicitly authorize breaking those persisted formats.
>
> Epicrypt 3 is developed and released **independently first**. Foundation is useful as architectural reference material, but Foundation extraction, adapter replacement, persistence migration and composition proof begin only **after Epicrypt 3.0 is released** and are not Epicrypt 3.0 release blockers.

---

## 1. Final product boundary

Epicrypt 3 becomes a reusable, transport-neutral authentication/security protocol core. It does **not** become an HTTP framework, ORM, database library, session framework, account system, consent UI or application authorization system.

### Epicrypt owns

- JWT/JWS/JWE/JWK/JWKS primitives and policy;
- token-class domain separation and key selection/rotation;
- OAuth 2.1 authorization request validation and protocol state machines;
- OAuth client model and protocol-level client authentication;
- Authorization Code + mandatory PKCE S256 semantics;
- Client Credentials semantics;
- Refresh Token rotation/reuse/revocation semantics;
- RFC 9068 JWT access-token issuance and resource-token validation;
- OAuth revocation/introspection/metadata semantics;
- DPoP proof validation/binding;
- OpenID Connect request/ID-token/UserInfo/discovery mechanics;
- generic first-party personal/API token issuance, abilities, verification and revocation semantics;
- public persistence contracts required for one-time use, replay protection, revocation and rotation;
- transport-neutral request/result/error DTOs and endpoint capability metadata.

### Framework/application owns

- route paths and HTTP router registration;
- request/header/body/query parsing and HTTP response emission;
- login/authentication UI and authenticated-subject acquisition;
- consent UI and application authorization decisions;
- account/user repositories and principal mapping;
- database/cache implementations of Epicrypt store contracts;
- backend transactions/locking implementation;
- sessions/cookies;
- application permission mapping/business authorization;
- rate limiting, audit, observability and telemetry;
- environment/config/file loading;
- deployment key/secret location policy;
- tenant/client administration policy outside protocol fields.

### Hard rule

A framework adapter may adapt transport and persistence, but must not reimplement PKCE, grant validation, auth-token claims, refresh reuse detection, OIDC nonce/hash rules, access-token validation, DPoP or personal-token ability semantics.

---

## 2. Three first-class authentication paths

Epicrypt 3 exposes three distinct but interoperable paths over one JOSE/key substrate:

```text
                         Epicrypt JOSE / Keys
                    JWT + JWS + JWE + JWK + JWKS
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
        OAuth 2.1             OIDC 1.0          Generic API/PAT
      protocol core        identity layer       personal-token core
             │                    │                    │
       at+jwt / JWE          ID Token JWT             pat+jwt
       refresh JWE            UserInfo claims      abilities + jti
       auth-code JWE              │             stateful revocation
             └────────────────────┴────────────────────┘
                                  │
                    public persistence contracts
                       (no DB implementation)
```

### OAuth 2.1 required grants

- Authorization Code + PKCE S256;
- Client Credentials;
- Refresh Token.

Explicitly excluded from 3.0:

- Resource Owner Password Credentials;
- OAuth implicit grant;
- PKCE `plain`;
- bearer credentials in query strings;
- wildcard/partial redirect matching.

### OIDC 1.0 profile

- Authorization Code flow only;
- `openid` scope activation;
- nonce, `max_age`, `auth_time`, `acr`, `amr` support;
- signed ID Token mandatory;
- `sub`, `aud`, `azp`, `at_hash`, `c_hash` as applicable;
- UserInfo claim projection;
- provider discovery;
- static client metadata for ID-token policy;
- optional encrypted ID Token only when explicitly configured and independently interoperable.

### Generic personal/API token profile

- application-defined subject;
- human-readable bounded name/label;
- bounded abilities with exact matching;
- optional expiration;
- JWT `jti` identity and private `pat+jwt` type;
- authoritative active/revoked record;
- issue/list/verify/revoke/revoke-all;
- optional bounded last-used capability without mandatory write-on-read;
- raw JWT returned only at issuance and never required in persistence.

---

## 3. 3.0 API and compatibility policy

Until the 3.0 release tag exists:

1. Prefer the clean final public API over compatibility aliases.
2. Remove superseded unreleased classes instead of maintaining two lifecycle implementations.
3. Do not retain an old namespace merely because earlier development commits exposed it.
4. No permanent dual-format auth credential support is required for unreleased Epicrypt 3 auth artifacts.
5. Public API inventory must record intentional removals/renames while the release is being prepared.
6. Durable 2.x cryptographic formats already frozen by tests remain a separate format-level compatibility contract.

Current example: refresh-specific `Token\Opaque\RefreshToken*` classes were removed and replaced by the final OAuth JOSE lifecycle under `Auth\OAuth`; generic `Token\Opaque\OpaqueToken` remains because it is a general-purpose primitive rather than an OAuth refresh lifecycle.

---

## 4. Standards baseline

### OAuth

- OAuth 2.1: `draft-ietf-oauth-v2-1-15` baseline at plan creation; perform a final latest-draft/RFC delta review before release.
- RFC 9700 — OAuth 2.0 Security Best Current Practice.
- RFC 7636 — PKCE; Epicrypt profile requires S256.
- RFC 8414 — Authorization Server Metadata.
- RFC 9207 — Authorization Server Issuer Identification where applicable.
- RFC 7009 — Token Revocation.
- RFC 7662 — Token Introspection.
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens.
- RFC 7523 — JWT client authentication/assertions as applicable.
- RFC 9449 — DPoP.

Do not advertise a finalized “OAuth 2.1 RFC compliant” claim while OAuth 2.1 remains an Internet-Draft.

### OpenID Connect

- OpenID Connect Core 1.0 incorporating Errata Set 2;
- OpenID Connect Discovery 1.0 incorporating Errata Set 2;
- JOSE standards already implemented by Epicrypt.

Dynamic Client Registration, logout profiles and federation are not 3.0 requirements.

---

## 5. Token classes and wire profiles

| Credential | 3.0 representation | Authoritative state |
| --- | --- | --- |
| OAuth access token | RFC 9068-style signed JWT, `typ=at+jwt` | optional/required status lookup by deployment policy |
| OAuth authorization code | short-lived JWE with bounded JWT-style claims | mandatory atomic one-time consume by code `jti` |
| OAuth refresh token | confidentiality-preserving compact JWE | mandatory family/token history, rotation and reuse detection |
| OIDC ID Token | signed JWT; optional JWE | normally stateless after issue |
| DPoP proof | signed JWT per RFC 9449 | replay store required |
| OAuth client assertion | signed JWT | replay/audience/time validation required |
| Personal/API token | signed JWT, `typ=pat+jwt` | mandatory active/revoked record keyed by `jti` |
| existing `PurposeToken` | existing signed-payload family | unchanged and non-interchangeable |

### Cross-token substitution

Every verifier binds:

- token class / `typ`;
- issuer where applicable;
- intended audience;
- key purpose;
- allowed algorithm family;
- required claims;
- token-specific `token_use`/purpose marker when type alone is insufficient.

An OAuth access token must fail as a personal token, ID Token, authorization code or refresh token. A personal token must fail as OAuth bearer authorization even when the JOSE algorithm is identical.

### Separate key purposes

```text
oauth.access-token.signing.v1
oauth.authorization-code.protection.v1
oauth.refresh-token.protection.v1
oidc.id-token.signing.v1
oidc.id-token.encryption.v1
api.personal-token.signing.v1
```

Frameworks may deliberately map more than one purpose to the same external key only through explicit configuration; Epicrypt APIs keep the domains distinct.

---

## 6. Implemented auth substrate ledger

| Capability | State | Evidence |
| --- | --- | --- |
| Explicit auth token classes/media types | Complete | `2b9c18e7` |
| Cross-token type substitution policy/tests | Complete | `2b9c18e7` |
| Auth-specific KeyRing purpose domains | Complete | `0b0a9d7b` |
| OAuth/OIDC JWT verification uses token-specific key purpose | Complete | `0b0a9d7b` |
| RFC 9068 access-token profile | Existing profile audited and hardened | baseline + `2b9c18e7`, `0b0a9d7b` |
| Authorization-code JWE artifact | Complete | `400497b3` |
| Refresh-token JWE artifact | Complete | `c1b30119` |
| Refresh-token authoritative family lifecycle | Complete | `168c7b3e` |
| Legacy refresh-specific `Token\Opaque` API | Removed before 3.0 | `168c7b3e` |
| Refresh-store reusable conformance coverage | Complete | `168c7b3e` |
| Central OAuth/OIDC/PAT input/claim limit policy | Pending | next batch |

The completed refresh lifecycle preserves consumed-history reuse detection, family-wide compromise revocation, client/DPoP sender binding, scope narrowing, idle/absolute expiry, exact successor-state persistence and collision handling. A successfully decrypted refresh JWE is only cryptographically valid; store state remains authoritative.

---

## 7. OAuth authorization-code artifact requirements

Authorization codes are short-lived, confidentiality-preserving JOSE artifacts with:

- stable unique code ID / `jti`;
- authorization/subject identity;
- client ID;
- exact redirect URI binding or cryptographic digest;
- mandatory PKCE S256 challenge;
- scopes and audiences;
- issuance/expiry bounds;
- optional OIDC transaction data such as nonce/authentication context.

The JWE is not sufficient for one-time semantics. `AuthorizationCodeStoreInterface` must provide atomic consume by authenticated code state; a valid JWE with a consumed `jti` is invalid.

---

## 8. OAuth refresh-token lifecycle requirements

The final 3.0 refresh path is `Auth\OAuth`, not `Token\Opaque`.

Required public concepts:

```text
RefreshTokenArtifact
RefreshTokenArtifactClaims
RefreshTokenArtifactIssue
RefreshTokenGrant
RefreshTokenRecord
RefreshTokenStoreInterface
RefreshTokenManager
RefreshTokenRotationResult
RefreshTokenRotationStatus
```

Rules:

- compact JWE uses the dedicated refresh-protection key purpose;
- JWE binds token ID, family ID, authorization ID, subject, client, audiences, scopes, `iat`, absolute expiry, idle expiry and optional DPoP thumbprint;
- raw JWE is never persisted;
- authoritative record is keyed by authenticated token ID / `jti`;
- `rotate()` atomically validates current state, consumes it and persists the **exact successor record represented by the newly issued JWE**;
- consumed history is retained through the authorization lifetime;
- reuse of a consumed ancestor revokes the entire family;
- family revocation and consumed-token reuse detection take precedence over idle expiry;
- client or sender mismatch never consumes the token;
- scope may only stay equal or narrow;
- concurrent double spend may produce only one active successor;
- replacement token/family uniqueness conflicts are explicit and do not consume current state.

No digest-of-raw-JWE compatibility layer is required for 3.0.

---

## 9. OAuth client/authentication target

Epicrypt defines a bounded framework-neutral client record containing protocol data only:

- client ID;
- public/confidential type;
- enabled status;
- exact redirect URIs;
- allowed grants;
- allowed scopes/resource audiences;
- allowed client-auth methods;
- secret-hash metadata where symmetric authentication is used;
- client JWK/JWKS material/reference for `private_key_jwt`;
- OIDC metadata required for ID-token policy;
- bounded token lifetime overrides.

Initial 3.0 client authentication:

- no client authentication for public clients where permitted;
- `client_secret_basic`;
- `client_secret_post` only when explicitly enabled;
- `private_key_jwt`.

Rules:

- simultaneous credentials through multiple methods fail;
- raw client secrets are never recoverable from stores;
- assertion `iss/sub/aud/exp/iat/jti` are bounded and verified;
- assertion replay protection uses an explicit authoritative store;
- algorithm/key selection is pinned by client policy.

mTLS client authentication is deferred unless a concrete 3.0 consumer requirement is added with interoperability coverage.

---

## 10. Transport-neutral endpoint target

Epicrypt provides endpoint **operations**, never route registration.

Target services:

```text
OAuthAuthorizationEndpoint
OAuthTokenEndpoint
OAuthRevocationEndpoint
OAuthIntrospectionEndpoint
OAuthMetadataEndpoint
OAuthJwksEndpoint
OidcUserInfoEndpoint
OidcDiscoveryEndpoint
```

Each accepts typed protocol DTOs and returns typed results/errors. No PSR-7, Webrick, Symfony or Laravel transport type appears in core signatures.

Endpoint capability/catalog metadata may describe semantic endpoint names, supported methods/content types and metadata keys, but does not impose deployment paths.

### Protocol-safe error model

OAuth errors include bounded/safe fields only:

```text
error
error_description?
error_uri?
state?                    # only when safe to echo
redirect_allowed
http_authentication_failure
```

Expected invalid credentials should return typed results where practical. Raw tokens, secrets, assertions and backend exception text never appear in public protocol errors.

---

## 11. OAuth authorization endpoint target

Authorization request validation requires:

- exact registered redirect URI matching;
- `response_type=code` only;
- mandatory PKCE S256;
- bounded `client_id`, `redirect_uri`, `state`, `scope`, `audience` and extension parameters;
- duplicate parameter rejection at parser/adapter boundary;
- enabled-client/grant validation;
- allowed scope/audience selection;
- authorization-server issuer/mix-up protection where applicable;
- no redirect until client/redirect trust is established.

Epicrypt does not perform login or render consent. It returns typed interaction requirements such as authentication required, consent required, authorization ready or protocol failure. The framework supplies authenticated-subject and authorization-decision state back to the protocol core.

---

## 12. OAuth token endpoint target

Typed grant handlers:

```text
AuthorizationCodeGrant
ClientCredentialsGrant
RefreshTokenGrant
```

### Authorization Code exchange

- authenticate/identify client according to policy;
- atomically consume code;
- exact client + redirect binding;
- verify PKCE S256;
- confirm authorization remains active through the public contract/application decision;
- issue access token;
- optionally issue refresh token according to policy.

### Client Credentials

- confidential/authenticated clients only;
- no human-user subject masquerading;
- clear client subject convention/profile;
- bounded client/server-approved scopes and audiences;
- no refresh token by default.

### Refresh Token

- use completed JOSE lifecycle under `Auth\OAuth`;
- integrate the lifecycle result into OAuth token response/error semantics;
- all presentation failures map safely to `invalid_grant` at the protocol boundary while internal status remains observable for security/audit policy.

---

## 13. OAuth access token, revocation, introspection, metadata and DPoP

RFC 9068 access-token claims include, as applicable:

```text
iss
sub
aud
exp
iat
jti
client_id
scope
```

Verification requires `typ=at+jwt`, pinned algorithms, trusted issuer, required audience, bounded time/leeway, scope/client shape checks and DPoP `cnf` binding where sender constrained.

Revocation/introspection remain meaningful for JWT access tokens through authoritative token-status contracts:

- status keyed by issuer/class/`jti`, never raw JWT;
- RFC 7009 behavior must not leak token existence improperly;
- RFC 7662 combines cryptographic validity with authoritative status according to policy.

Authorization-server metadata and JWKS expose only enabled capabilities. Epicrypt never invents deployment URLs.

Existing DPoP primitives are integrated rather than rewritten:

- proof `typ`, JWK, algorithm, `htm`, normalized `htu`, `iat`, `jti`;
- replay store required;
- `cnf.jkt` binding at issuance/resource validation;
- `ath` where required;
- nonce only when a complete interoperable nonce policy exists.

---

## 14. OpenID Connect provider target

OIDC semantics activate only when `openid` is requested/approved and allowed.

Required provider behavior:

- nonce/prompt/max_age/acr request modeling;
- framework-neutral interaction requirements;
- ID Token issuer paired with existing `OpenIdIdTokenValidator`;
- issuer/client/audience/subject binding;
- `auth_time`, nonce, `acr`, `amr`, `azp` as required;
- `at_hash`, `c_hash` according to token/response context;
- `OidcSubjectIdentifierProviderInterface` for public/pairwise-capable subject policy;
- `OidcClaimsProviderInterface` + UserInfo projection;
- provider discovery derived from enabled profile and adapter-supplied endpoint URIs;
- optional ID-token encryption only after independent interoperability passes.

Application account IDs are not assumed to be public OIDC `sub` values.

---

## 15. Generic personal/API token target

Suggested final public surface:

```text
PersonalAccessTokenManager
PersonalAccessTokenIssue
PersonalAccessTokenResult
PersonalAccessTokenRecord
PersonalAccessTokenStoreInterface
PersonalAccessTokenPolicy
PersonalAccessTokenAbilities
```

JWT profile uses `typ=pat+jwt` and bounded claims such as:

```text
iss?
sub
jti
iat
exp?
name
abilities
token_use=personal_access
```

Rules:

- stateful verification by default for immediate revocation;
- exact ability matching;
- `*` means all only when explicitly permitted;
- no implicit hierarchical wildcard behavior;
- raw JWT never persisted;
- list returns metadata only;
- optional last-used update is a separate capability and never forces a write on every verification.

---

## 16. Persistence and concurrency contracts

Epicrypt ships **no production DBLayer, PDO, ORM, SQL, Redis or CacheLayer implementation** for auth protocol stores.

Test-only in-memory/fault stores are allowed under `tests/`.

Every public store interface documents:

- uniqueness keys;
- atomic operations;
- conflict outcomes;
- idempotency;
- expiry semantics;
- revocation semantics;
- whether stale reads are security-sensitive;
- consistency requirements for multi-process/distributed deployments.

Critical atomic boundaries:

- authorization-code consume;
- refresh-token consume/replace/reuse detection;
- refresh family revoke;
- DPoP/client-assertion replay claim;
- personal-token revoke/revoke-all versus verification;
- access-token status lookup when authoritative revocation is enabled.

No interface may imply that `find()` followed by unrelated `delete()` is sufficient for one-time credentials.

---

## 17. Central parser/limit policy

Auth input bounds must be centralized instead of scattered magic numbers. Reuse the design discipline of `JosePolicy` and introduce auth/OAuth/OIDC/PAT-specific immutable limits/policies.

Cover at least:

- total parameter count;
- parameter-name bytes;
- individual parameter value bytes;
- client ID, redirect URI, state, nonce, verifier and challenge bytes;
- scope count/item/total bytes;
- audience count/item/total bytes;
- authorization/subject identifier bytes;
- JWT/JWE compact size;
- auth claim count/depth/member count;
- client assertion lifetime/skew;
- personal-token name/ability count/item/total bytes;
- metadata/discovery size;
- public store list-result count.

Reject malformed/oversized input before expensive signature, decryption, password-hash or repository work whenever possible.

---

## 18. Testing, interoperability, mutation and performance

### Shared token/JOSE tests

- strict token-class substitution matrix;
- wrong issuer/audience/key purpose/algorithm;
- active/fallback key rotation;
- malformed/oversized JWT/JWE/JWK/JWKS;
- key/algorithm confusion;
- temporal boundaries/skew;
- sensitive-parameter/reflection audit.

### OAuth tests

- Authorization Code + S256 happy/negative paths;
- code replay/concurrent consume;
- redirect/verifier mismatch;
- public/confidential client rules;
- client secret/private-key JWT authentication;
- assertion replay;
- Client Credentials;
- scope/audience narrowing and escalation rejection;
- refresh rotation/reuse/concurrency/family revocation;
- access-token validation;
- revocation/introspection;
- RFC 9700 negative vectors;
- issuer/mix-up defenses where applicable.

### OIDC tests

- `openid` activation;
- nonce;
- audience/`azp`;
- `auth_time`/`max_age`;
- `acr`/`amr`;
- `at_hash`/`c_hash`;
- subject mapping;
- UserInfo projection;
- discovery;
- token-class substitution;
- encrypted ID-token interoperability if enabled.

### Personal token tests

- issue/verify/list;
- exact abilities/wildcard policy;
- expiry;
- revoke/revoke-all;
- concurrent revoke/verify semantics;
- metadata never leaks raw JWT;
- subject/class/key-purpose mismatch;
- optional last-used capability;
- persistent-worker/Fiber isolation.

### Independent interoperability

Use independent JOSE/JWT/OAuth/OIDC fixtures where feasible for RFC 9068, PKCE, `private_key_jwt`, DPoP, ID-token hashes, discovery/JWKS and malformed corpus behavior.

### Mutation/static/security gates

Dedicated mutation shards:

```text
oauth-authorization
oauth-token-grants
oauth-refresh-revocation
oauth-client-auth
oidc-provider
personal-access-token
```

Also require PHP 8.4/8.5 lowest/stable, analyzers/PHPForge, dependency audit, no secret-bearing diagnostics, complexity caps, no global mutable trust/request state and no framework/DB production dependency.

### Performance attribution

Measure separately:

1. JWT access-token issue/verify;
2. authorization-code JWE issue/consume;
3. refresh JWE parse + store rotation;
4. DPoP validation;
5. ID Token issue/verify;
6. personal token issue/verify + status lookup;
7. active versus fallback key verification;
8. persistent-worker repeated validation/memory growth;
9. capability-absent cost when auth services are not composed.

Database/network/KDF/HTTP cost is attributed separately from Epicrypt protocol/crypto cost.

---

## 19. Documentation deliverables

Before 3.0 release:

- architecture overview for OAuth/OIDC/PAT;
- OAuth 2.1 server-core guide;
- OIDC provider guide;
- personal/API token guide;
- framework-adapter guide;
- persistence-contract guide with atomicity requirements;
- key-purpose/rotation guide;
- security deployment checklist;
- standards matrix and intentional exclusions;
- framework/database-free examples;
- public API inventory and 2.x→3.0 migration notes;
- refresh-token docs updated from the removed opaque lifecycle to the final JOSE lifecycle.

Never market the personal-token core as Laravel Sanctum compatibility. It is a generic JWT personal-token system with Sanctum-style management semantics.

---

## 20. Implementation phases and checkboxes

### Phase A — Epicrypt rebaseline and API freeze

- [x] Capture Epicrypt regression/scope-extension baselines and retain the previous green release matrix as the non-regression floor. (`cca7e5a9`, `0ec87442`)
- [x] Inventory current Epicrypt JWT/JOSE/OIDC/DPoP/refresh primitives against the auth target architecture. (`8235274b` plan/inventory baseline)
- [x] Create the Epicrypt 3 public API inventory. (`docs/plans/epicrypt-3-public-api-inventory.md`)
- [x] Establish the pre-release 3.0 API rule: no source/API BC constraint until release; persisted frozen crypto formats remain separate compatibility contracts. (plan ledger)
- [ ] Keep the public API inventory synchronized through every remaining implementation batch and freeze it at release.

> Foundation source inventory/fixture freezing was intentionally removed from Phase A. It is deferred until post-release Foundation adoption and is not an Epicrypt 3.0 implementation dependency.

### Phase B — shared auth-token/JOSE substrate

- [x] Add explicit auth token classes/media types and cross-token substitution policy. (`2b9c18e7`)
- [x] Audit/harden the existing RFC 9068 JWT access-token profile. (baseline + `2b9c18e7`, `0b0a9d7b`)
- [x] Implement the JOSE authorization-code artifact profile. (`400497b3`)
- [x] Implement the JOSE refresh-token artifact profile. (`c1b30119`)
- [x] Complete authoritative refresh-family rotation/reuse lifecycle over the JOSE artifact. (`168c7b3e`)
- [x] Remove the superseded refresh-specific `Token\Opaque` API before 3.0; retain generic `OpaqueToken` only. (`168c7b3e`)
- [x] Add explicit key purposes for OAuth/OIDC/PAT credentials. (`0b0a9d7b`)
- [x] Add token-class/key-purpose/artifact substitution and security-negative tests. (`2b9c18e7`, `0b0a9d7b`, `400497b3`, `c1b30119`, `168c7b3e`)
- [ ] Centralize OAuth/OIDC/PAT parameter, token and claim bounds.

### Phase C — client/store/endpoint contracts

- [ ] Implement framework-neutral OAuth client model/policy.
- [ ] Implement client-secret verification and `private_key_jwt` validation/replay contract.
- [x] Define authoritative refresh-token store contract, exact replacement-state atomicity and reusable conformance semantics. (`168c7b3e`)
- [ ] Define authorization, authorization-code, access-token-status, consent/replay and personal-token store contracts.
- [ ] Define protocol request/response/error DTOs.
- [ ] Define endpoint catalog/capability metadata with no route registration.
- [x] Provide refresh-token test-only in-memory/conformance store. (`168c7b3e`)
- [ ] Provide remaining test-only in-memory/fault stores required by public contracts.

### Phase D — OAuth 2.1 authorization core

- [ ] Implement independent Epicrypt authorization request validator/state model.
- [ ] Exact redirect + code response + mandatory PKCE S256.
- [ ] Scope/audience bounded resolution hooks.
- [ ] Authentication/consent interaction result model.
- [ ] Add authorization-code authoritative store + atomic one-time consume.
- [ ] Integrate JOSE authorization-code issue + consume.
- [ ] OAuth protocol errors and redirect safety.
- [ ] RFC 9700 authorization negative vectors.

### Phase E — OAuth 2.1 token/core lifecycle

- [ ] Authorization Code exchange.
- [ ] Client Credentials.
- [x] JWT/JWE refresh-token rotation/reuse state machine. (`168c7b3e`)
- [ ] Integrate refresh grant into the OAuth token endpoint/result model.
- [ ] JWT access-token issuance/validation service over the existing RFC 9068 profile.
- [ ] Revocation.
- [ ] Introspection.
- [ ] Authorization-server metadata.
- [ ] JWKS publication scoped to auth signing purposes.
- [ ] Integrate DPoP into issuance/resource validation.
- [ ] Dedicated OAuth mutation/interoperability gates.

### Phase F — OpenID Connect 1.0 provider

- [ ] OIDC request extensions and `openid` activation.
- [ ] Interaction requirements for nonce/prompt/max_age/acr.
- [ ] ID Token issuer paired with existing validator.
- [ ] Subject identifier provider contract.
- [ ] UserInfo claims provider/projection.
- [ ] OIDC discovery metadata.
- [ ] Optional encrypted ID Token only if independent interoperability passes.
- [ ] OIDC negative/conformance vectors and mutation gate.

### Phase G — generic personal/API tokens

- [ ] Finalize public generic naming/API.
- [ ] `pat+jwt` profile and separate key-purpose enforcement.
- [ ] Issue/verify/list/revoke/revoke-all service.
- [ ] Bounded exact abilities + explicit wildcard policy.
- [ ] Authoritative store contract; raw JWT never persisted.
- [ ] Optional last-used capability without forced write-on-read.
- [ ] State/concurrency/Fiber/persistent-runtime tests.
- [ ] Dedicated mutation/performance coverage.

### Phase H — Epicrypt release integration/hardening

- [ ] Complete standards delta review for the latest OAuth 2.1 draft/RFC at release time.
- [ ] Complete OIDC Core/Discovery Errata 2 requirements matrix.
- [ ] Run all pre-auth Epicrypt regression gates.
- [ ] Run OAuth/OIDC/PAT mutation shards.
- [ ] Run PHP 8.4/8.5 lowest/stable QA and analyzers.
- [ ] Run independent JOSE/OAuth/OIDC interoperability vectors.
- [ ] Run performance attribution and persistent-runtime memory checks.
- [ ] Complete docs/migration/public API inventory.
- [ ] Verify no obsolete unreleased compatibility surfaces remain.
- [ ] Mark the exact final SHA release-ready only after the complete Epicrypt gate is green.
- [ ] Release Epicrypt 3.0.

### Deferred post-release — Foundation adoption

> **Not an Epicrypt 3.0 release gate. Start only after Epicrypt 3.0 has been released.**

- [ ] Rescan Foundation OAuth/OIDC/auth source, contracts, stores, routes, schema and tests against released Epicrypt 3.0.
- [ ] Produce move/keep/replace inventory from the released Epicrypt API.
- [ ] Freeze Foundation OAuth behavior/migration vectors where persisted production state requires evidence.
- [ ] Add Foundation DBLayer implementations of released Epicrypt store contracts.
- [ ] Replace Foundation protocol mechanics with Epicrypt services.
- [ ] Keep Foundation routes/Webrick/login/consent/audit/rate-limit/config/principal mapping/application policy only.
- [ ] Remove obsolete Foundation Epicrypt/OAuth indirection where direct consumption is cleaner.
- [ ] Migrate/preserve existing Foundation OAuth state only where real persisted evidence requires it.
- [ ] Close Foundation Pathwise/Epicrypt dependency acceptance and remaining Epicrypt-dependent OTP/Passkey work.
- [ ] Run Foundation PHP 8.4/8.5 composition/integration gates.
- [ ] Update Foundation plan/docs to make released Epicrypt the OAuth/OIDC/PAT protocol owner.

---

## 21. Immediate next batch

**Continue Epicrypt only. Do not start Foundation adoption.**

1. Centralize OAuth/OIDC/PAT parameter, token and claim bounds and migrate the new authorization-code/refresh artifact constants to that policy where appropriate.
2. Add the authorization-code authoritative store contract and atomic one-time consume semantics with reusable in-memory/conformance coverage.
3. Define the remaining store/client contracts needed before the authorization/token endpoint state machines.
4. Keep this plan and the public API inventory synchronized after each implementation commit.
5. Run focused syntax/tests available in the current environment; keep full CI/release gates unchecked until independently green.

---

## 22. Final target

Epicrypt 3 is complete when a framework can implement only transport/application/persistence adapters and obtain all three secure authentication paths from one reusable core:

```text
Framework / application
  ├── routes + HTTP adaptation
  ├── login + consent UI
  ├── account/principal mapping
  ├── DB/cache store implementations
  ├── audit/rate-limit/config
  │
  └── Epicrypt 3
       ├── OAuth 2.1 protocol core
       │    ├── Authorization Code + PKCE
       │    ├── Client Credentials
       │    ├── Refresh rotation/reuse
       │    ├── at+jwt access tokens
       │    ├── revocation/introspection/metadata
       │    └── DPoP
       │
       ├── OpenID Connect 1.0 provider
       │    ├── ID Token
       │    ├── UserInfo
       │    └── discovery
       │
       └── Generic personal/API token core
            ├── pat+jwt
            ├── abilities
            └── list/revoke lifecycle
```

No framework should need to reimplement protocol cryptography or authoritative auth state-machine semantics above this surface.
