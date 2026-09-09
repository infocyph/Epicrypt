# Epicrypt 3 — Final Authentication Protocol Development Plan

**Status:** Active implementation plan  
**Target:** Epicrypt 3.0  
**Branch:** `epicrypt-3/architecture-plan`  
**Regression baseline:** `cca7e5a93f8b5f37329053b448fbce91e9496262`  
**Auth scope-extension baseline:** `0ec8744232f1c67f776a8fbd5414eee7a01369ab`  
**Priority:** standards correctness → security → deterministic state semantics → framework neutrality → performance → ergonomics

> Epicrypt 3.0 is unreleased. Source/API backward compatibility is not a design constraint until the 3.0 release. Prefer the clean final API and remove superseded development surfaces rather than carrying aliases or parallel implementations.
>
> Persisted cryptographic compatibility is separate. Frozen Epicrypt 2.x `ep2` string/file formats and signed-payload v2 fixtures stay supported where already established as durable format contracts.
>
> Epicrypt 3 is implemented and released independently first. Foundation is reference material only during this work; Foundation extraction/adapters/migration begin after Epicrypt 3.0 and are not Epicrypt release blockers.

---

## 1. Product boundary

Epicrypt 3 is a reusable, transport-neutral authentication/security protocol core.

### Epicrypt owns

- JWT/JWS/JWE/JWK/JWKS primitives and policy;
- auth-token class separation and key-purpose isolation;
- OAuth 2.1 authorization/token protocol mechanics;
- framework-neutral OAuth client model and client authentication;
- Authorization Code + mandatory PKCE S256;
- Client Credentials;
- refresh rotation/reuse/revocation state machine;
- RFC 9068 JWT access tokens;
- revocation/introspection/authorization-server metadata;
- DPoP proof validation and access-token binding;
- OIDC request, ID-token, UserInfo and discovery mechanics;
- generic personal/API token issue, abilities, verification and revocation;
- public persistence contracts for one-time/replay/revocation state;
- transport-neutral protocol DTOs/results/errors and endpoint capability metadata.

### Framework/application owns

- routes and HTTP adaptation;
- login/authentication UI and authenticated-subject acquisition;
- consent UI/application decision and consent-history persistence;
- account/user repositories and principal mapping;
- DB/cache implementations of Epicrypt stores and transaction/locking mechanics;
- sessions/cookies;
- application authorization/permission mapping;
- rate limiting/audit/telemetry;
- environment/config/file loading and deployment key locations;
- tenant/client administration outside protocol fields.

A framework may adapt transport/persistence but must not reimplement PKCE, token claims, refresh reuse detection, OIDC nonce/hash rules, access-token verification, DPoP or PAT ability semantics.

---

## 2. Authentication paths and wire profiles

### OAuth 2.1

Required grants:

- Authorization Code + PKCE S256;
- Client Credentials;
- Refresh Token.

Excluded from 3.0: password grant, implicit grant, PKCE `plain`, query-string bearer tokens and partial/wildcard redirect matching.

### OpenID Connect 1.0

Authorization Code flow only, activated by `openid`; nonce/max_age/auth_time/acr/amr, signed ID Token, `sub`/`aud`/`azp`, `at_hash`/`c_hash`, UserInfo and discovery. Optional ID-token encryption only after independent interoperability passes.

### Generic personal/API token

Framework-neutral Sanctum-style semantics: issue/list/verify/revoke/revoke-all, bounded exact abilities, optional expiry, stateful `jti` revocation, optional bounded last-used capability, raw JWT returned only at issue.

### Wire profiles

| Credential | Representation | Authoritative state |
| --- | --- | --- |
| OAuth access token | RFC 9068 signed JWT, `typ=at+jwt` | optional/required status policy |
| OAuth authorization code | short-lived compact JWE | mandatory atomic consume by `jti` |
| OAuth refresh token | compact JWE | family/token history, rotation/reuse |
| OIDC ID Token | signed JWT; optional JWE | normally stateless after issue |
| DPoP proof | signed JWT | replay store |
| OAuth client assertion | signed JWT | replay store + registered client key policy |
| Personal/API token | signed JWT, `typ=pat+jwt` | active/revoked record by `jti` |
| existing `PurposeToken` | existing signed-payload family | unchanged/non-interchangeable |

Cross-token substitution is rejected by `typ`, issuer/audience, dedicated key purpose, algorithm policy, required claims and token-specific use markers.

Key-purpose domains:

```text
oauth.access-token.signing.v1
oauth.authorization-code.protection.v1
oauth.refresh-token.protection.v1
oidc.id-token.signing.v1
oidc.id-token.encryption.v1
api.personal-token.signing.v1
```

---

## 3. Standards baseline

OAuth baseline:

- OAuth 2.1 `draft-ietf-oauth-v2-1-15` at plan creation; recheck latest draft/RFC before release;
- RFC 9700 Security BCP;
- RFC 7636 PKCE, S256-only Epicrypt profile;
- RFC 8414 metadata;
- RFC 9207 issuer identification where applicable;
- RFC 7009 revocation;
- RFC 7662 introspection;
- RFC 9068 JWT access tokens;
- RFC 7523 JWT client authentication/assertions;
- RFC 9449 DPoP.

OIDC baseline:

- OpenID Connect Core 1.0 incorporating Errata Set 2;
- OpenID Connect Discovery 1.0 incorporating Errata Set 2.

Do not claim finalized OAuth 2.1 RFC compliance while it remains an Internet-Draft.

---

## 4. 3.0 API/compatibility policy

Until 3.0 release:

1. clean final API beats source/API compatibility;
2. remove superseded unreleased symbols instead of adding shims;
3. no dual auth credential formats solely for intermediate 3.0 development commits;
4. update the public API inventory after every public batch;
5. durable frozen cryptographic formats retain their separate compatibility lifecycle.

Current example: refresh-specific `Token\Opaque\RefreshToken*` was removed and replaced by `Auth\OAuth\RefreshToken*`; generic `Token\Opaque\OpaqueToken` remains.

---

## 5. Implemented authentication ledger

| Capability | State | Evidence |
| --- | --- | --- |
| auth token classes/media types + substitution policy | Complete | `2b9c18e7` |
| auth-specific KeyRing purposes + verifier binding | Complete | `0b0a9d7b` |
| RFC 9068 access-token profile audit/hardening | Complete | baseline + `2b9c18e7`, `0b0a9d7b` |
| authorization-code JWE artifact | Complete | `400497b3` |
| refresh-token JWE artifact | Complete | `c1b30119` |
| refresh authoritative family lifecycle + store conformance | Complete | `168c7b3e` |
| legacy refresh-specific `Token\Opaque` API removal | Complete | `168c7b3e` |
| centralized OAuth/OIDC/PAT hard bounds | Complete | `2b9c1c02` |
| authorization-code exact-state atomic consume | Complete | `8326444e` |
| framework-neutral OAuth client model/store | Complete | `d2ff4c81` |
| client-secret + strict `private_key_jwt` + replay | Complete | `5c01d1bb` |
| authorization/access-token-status/PAT authoritative state contracts | Complete | `143b1c21` |
| authorization request/result/error DTOs | Complete for authorization endpoint | `ad14609c` |
| endpoint capability catalog | Complete | `ad14609c` |
| authorization request validator: duplicate-safe input, exact redirect, code-only, S256 PKCE, scope subset | Complete | `ad14609c` |
| authorization redirect-error safety | Complete initial core | `ad14609c` |

### Store/concurrency decisions

- Raw authorization-code JWE is never persisted. `AuthorizationCodeStoreInterface` atomically compares exact authenticated state and distinguishes consumed/replayed/expired/invalid.
- Raw refresh JWE is never persisted. Refresh state remains authoritative and consumed ancestry is retained through authorization lifetime for family-wide reuse detection.
- `OAuthAuthorizationStoreInterface` owns approved authorization activity/revocation.
- `OAuthAccessTokenStatusStoreInterface` is an optional authoritative `jti` status layer for deployments needing immediate JWT revocation.
- `PersonalAccessTokenStoreInterface` owns metadata-only PAT state/list/revoke/revoke-all; raw PAT JWTs are never persisted.
- Client-assertion and DPoP replay reuse the existing `JwtReplayStoreInterface`; no OAuth-specific duplicate replay abstraction will be added.
- Epicrypt does not require a consent-history store. Consent UI/history is application policy; Epicrypt consumes the resulting approved authorization state.
- Security-sensitive active/revoked reads must not be served from stale ordinary caches after a revocation/disablement commit.

---

## 6. Remaining architecture target

### Authorization core next

- scope/audience resolution hook that lets the application map validated requested scopes to allowed resource audiences without moving permission policy into Epicrypt;
- typed authentication/consent interaction requirements;
- integrate approved authorization state with authorization-code JWE issue + atomic code-store create;
- strengthen RFC 9700 authorization negatives and malformed/bounded input coverage;
- keep safe redirect semantics centralized in protocol result objects.

### Token/core lifecycle

Typed Authorization Code, Client Credentials and Refresh Token handlers; exact client/redirect/PKCE validation before code consume; refresh handler over completed JOSE lifecycle; RFC 9068 access-token issue/verify; revocation/introspection/metadata/JWKS; DPoP binding.

### OIDC provider

`openid` activation, nonce/prompt/max_age/acr interaction requirements, ID Token issuer paired with current validator, subject identifier provider, UserInfo claims provider/projection and discovery.

### Personal/API token core

Final manager/policy/abilities/JWT profile over the already-landed authoritative PAT store contract.

---

## 7. Persistence/concurrency rules

Epicrypt ships no production DB/ORM/SQL/Redis/CacheLayer implementation for auth stores. Test-only stores live under `tests/`.

Every public store contract documents uniqueness, atomic operations, conflicts, expiry, idempotency, revocation, stale-read sensitivity and multi-process consistency.

Critical atomic boundaries:

- authorization-code consume;
- refresh consume/replace/reuse detection and family revoke;
- DPoP/client-assertion replay claim;
- PAT revoke/revoke-all versus verification/issue;
- access-token status lookup when authoritative;
- OAuth authorization revocation versus token/code issuance.

---

## 8. Test/interoperability/security gates

Required coverage includes:

- token-class substitution and wrong issuer/audience/key purpose/algorithm;
- active/fallback key rotation;
- malformed/oversized auth and JOSE input;
- duplicate OAuth parameters, PKCE, exact redirect, redirect-error safety and code replay/concurrent consume;
- public/confidential client-auth rules and assertion replay;
- Client Credentials;
- refresh rotation/reuse/concurrency/family revocation;
- RFC 9068 access validation;
- revocation/introspection and RFC 9700 negatives;
- OIDC nonce/azp/auth_time/max_age/acr/amr/hash/sub/UserInfo/discovery;
- PAT abilities/expiry/revoke/revoke-all/concurrency/Fiber/persistent worker;
- independent JOSE/OAuth/OIDC vectors where feasible.

Mutation shards:

```text
oauth-authorization
oauth-token-grants
oauth-refresh-revocation
oauth-client-auth
oidc-provider
personal-access-token
```

Release QA: PHP 8.4/8.5 lowest/stable, analyzers/PHPForge, dependency audit, no secret-bearing diagnostics, complexity caps, no global mutable request/trust state, and no framework/DB production dependency.

Performance attribution separately measures access-token issue/verify, code JWE issue/consume, refresh JWE+rotation, DPoP, ID Token, PAT store validation, active/fallback key verification and persistent-worker memory.

---

## 9. Documentation deliverables

Before release update/add:

- auth architecture overview;
- OAuth server-core guide;
- OIDC provider guide;
- personal/API token guide;
- framework-adapter guide;
- persistence/atomicity guide;
- key-purpose/rotation guide;
- security deployment checklist;
- standards matrix/exclusions;
- framework/database-free examples;
- 2.x→3.0 migration/public API inventory;
- refresh documentation migrated from removed opaque lifecycle to final JOSE lifecycle.

---

## 10. Implementation phases/checklist

### Phase A — Epicrypt rebaseline/API discipline

- [x] Capture regression/scope-extension baselines and preserve prior green release matrix. (`cca7e5a9`, `0ec87442`)
- [x] Inventory current JWT/JOSE/OIDC/DPoP/refresh primitives. (`8235274b` planning baseline)
- [x] Create Epicrypt 3 public API inventory.
- [x] Establish no-source/API-BC-before-3.0 rule while preserving frozen persisted formats. (`0aff2ae5`)
- [ ] Keep public API inventory synchronized after each public batch and freeze it at release. (ongoing; synchronized through `ad14609c` by the following docs commit)

### Phase B — auth-token/JOSE substrate

- [x] Explicit auth token classes/media types and substitution policy. (`2b9c18e7`)
- [x] RFC 9068 profile audit/hardening. (baseline + `2b9c18e7`, `0b0a9d7b`)
- [x] Authorization-code JWE profile. (`400497b3`)
- [x] Refresh-token JWE profile. (`c1b30119`)
- [x] Refresh authoritative lifecycle + store conformance. (`168c7b3e`)
- [x] Remove superseded opaque refresh API. (`168c7b3e`)
- [x] Auth key-purpose isolation. (`0b0a9d7b`)
- [x] Token/artifact substitution/security-negative tests. (`2b9c18e7`, `0b0a9d7b`, `400497b3`, `c1b30119`, `168c7b3e`)
- [x] Centralize shared OAuth/OIDC/PAT hard bounds. (`2b9c1c02`)

### Phase C — client/store/endpoint contracts

- [x] Framework-neutral OAuth client model/policy and read-only client store. (`d2ff4c81`)
- [x] Client-secret verification and `private_key_jwt` validation/replay. (`5c01d1bb`)
- [x] Refresh-token authoritative store + replacement atomicity/conformance. (`168c7b3e`)
- [x] Authorization-code authoritative store + exact-state atomic consume/conformance. (`8326444e`)
- [x] Authorization/client/access-token-status/PAT state contracts. (`d2ff4c81`, `143b1c21`)
- [x] Reuse `JwtReplayStoreInterface`; do not add OAuth-specific replay store. (`5c01d1bb`)
- [x] Keep consent persistence application-owned; Epicrypt stores approved authorization state only. (`143b1c21` architecture decision)
- [x] Authorization request/result/error DTOs. (`ad14609c`)
- [ ] Remaining token/revocation/introspection/OIDC/PAT endpoint DTOs as their phases are implemented.
- [x] Endpoint capability catalog with no route registration. (`ad14609c`)
- [x] Test-only client/refresh/code/authorization/access-status/PAT in-memory stores. (`d2ff4c81`, `168c7b3e`, `8326444e`, `143b1c21`)
- [ ] Reusable fault/concurrency stores still needed by later mutation/concurrency batches.

### Phase D — OAuth authorization core

- [x] Independent Epicrypt authorization request model/validator. (`ad14609c`)
- [x] Bounded duplicate-safe parameter envelope. (`ad14609c`)
- [x] Exact redirect + `response_type=code` + mandatory PKCE S256. (`ad14609c`)
- [x] Client grant + requested-scope subset validation. (`ad14609c`)
- [ ] Scope/audience resolution hook and final audience binding.
- [ ] Authentication/consent interaction model.
- [x] Authorization-code authoritative one-time consume primitive. (`8326444e`)
- [ ] Integrate approved authorization + authorization-code JWE issue/store service.
- [x] OAuth authorization errors/initial redirect safety. (`ad14609c`)
- [ ] Full RFC 9700 authorization negative vectors/mutation coverage.

### Phase E — OAuth token/core lifecycle

- [ ] Authorization Code exchange.
- [ ] Client Credentials.
- [x] Refresh-token rotation/reuse state machine. (`168c7b3e`)
- [ ] Integrate refresh grant into OAuth token endpoint/result model.
- [ ] Access-token issuance/validation service over RFC 9068 profile.
- [ ] Revocation.
- [ ] Introspection.
- [ ] Authorization-server metadata.
- [ ] Auth-scoped JWKS publication.
- [ ] DPoP issuance/resource integration.
- [ ] OAuth mutation/interoperability gates.

### Phase F — OpenID Connect provider

- [ ] OIDC request extensions/`openid` activation.
- [ ] nonce/prompt/max_age/acr interaction requirements.
- [ ] ID Token issuer paired with current validator.
- [ ] subject identifier provider contract.
- [ ] UserInfo claims provider/projection.
- [ ] discovery metadata.
- [ ] optional encrypted ID Token only after interoperability.
- [ ] OIDC conformance/negative/mutation coverage.

### Phase G — generic personal/API tokens

- [ ] Final public naming/API beyond authoritative record/store already landed.
- [ ] `pat+jwt` profile + key-purpose enforcement.
- [ ] issue/verify/list/revoke/revoke-all manager semantics.
- [ ] exact abilities + explicit wildcard policy.
- [x] authoritative metadata store; raw JWT never persisted. (`143b1c21`)
- [ ] optional last-used capability.
- [ ] concurrency/Fiber/persistent-runtime coverage.
- [ ] mutation/performance coverage.

### Phase H — Epicrypt release hardening

- [ ] Latest OAuth 2.1 draft/RFC delta review.
- [ ] OIDC Core/Discovery Errata 2 requirements matrix.
- [ ] Pre-auth Epicrypt regression gates.
- [ ] OAuth/OIDC/PAT mutation shards.
- [ ] PHP 8.4/8.5 lowest/stable QA/analyzers.
- [ ] Independent interoperability vectors.
- [ ] Performance/persistent-runtime memory checks.
- [ ] Complete docs/migration/API inventory.
- [ ] Remove obsolete unreleased compatibility surface.
- [ ] Mark exact final SHA release-ready only after complete Epicrypt gates are green.
- [ ] Release Epicrypt 3.0.

### Deferred after 3.0 release — Foundation adoption

**Not an Epicrypt 3 release gate.**

- [ ] Rescan Foundation auth/OAuth source/contracts/stores/routes/schema/tests against released Epicrypt 3.
- [ ] Produce move/keep/replace inventory and migration vectors where persisted state requires them.
- [ ] Add Foundation DBLayer implementations of released store contracts.
- [ ] Replace Foundation protocol mechanics with Epicrypt services while retaining transport/login/consent/audit/rate-limit/config/principal/application policy.
- [ ] Remove obsolete Foundation auth/Epicrypt indirection and migrate persisted state only where evidence requires it.
- [ ] Close Foundation Epicrypt/Pathwise and Epicrypt-dependent OTP/Passkey acceptance work.
- [ ] Run Foundation PHP 8.4/8.5 composition gates and update Foundation plan/docs.

---

## 11. Immediate next batch

**Epicrypt only.**

1. Add the authorization scope→audience resolution contract and validate returned scopes/audiences against client registration.
2. Add typed authentication/consent interaction requirements without adding application consent persistence.
3. Integrate approved `OAuthAuthorizationRecord` state with authorization-code JWE issue + atomic `AuthorizationCodeStoreInterface::create()`.
4. Expand authorization negative vectors around duplicate/oversized parameters, disabled clients, redirect selection, PKCE, scope/audience and safe redirect behavior.
5. Then continue into Authorization Code token exchange and the rest of Phase E.
6. Keep the plan/API inventory synchronized after each public batch; full CI/release gates remain unchecked until independently green.

---

## 12. Final target

Epicrypt 3 is complete when a framework implements only transport/application/persistence adapters and receives secure OAuth 2.1, OIDC 1.0 and generic personal/API token paths from Epicrypt without reimplementing protocol cryptography or authoritative auth state-machine semantics.
