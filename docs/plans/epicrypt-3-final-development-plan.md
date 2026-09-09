# Epicrypt 3 — Final Authentication Protocol Development Plan

**Status:** Active implementation plan  
**Target:** Epicrypt 3.0  
**Branch:** `epicrypt-3/architecture-plan`  
**Regression baseline:** `cca7e5a93f8b5f37329053b448fbce91e9496262`  
**Auth scope-extension baseline:** `0ec8744232f1c67f776a8fbd5414eee7a01369ab`  
**Priority:** standards correctness → security → deterministic state semantics → framework neutrality → performance → ergonomics

> Epicrypt 3.0 is unreleased. Source/API backward compatibility is **not** a design constraint until the 3.0 release. Prefer the clean final API and remove superseded development surfaces rather than carrying aliases, compatibility shims, or parallel implementations.
>
> Persisted cryptographic compatibility is separate. Frozen Epicrypt 2.x `ep2` string/file formats and signed-payload v2 fixtures remain supported where already established as durable format contracts.
>
> Epicrypt 3 is implemented and released independently first. Foundation is reference material only during this work. Foundation adoption, persistence adapters, migration, and integration begin after Epicrypt 3.0 is released.

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
- OIDC request, ID-token, UserInfo, and discovery mechanics;
- generic personal/API token issue, abilities, verification, and revocation;
- public persistence contracts for one-time/replay/revocation state;
- transport-neutral request/result/error/capability DTOs.

### Framework/application owns

- routes and HTTP adaptation;
- login/authentication UI and authenticated-subject acquisition;
- consent UI/application decision and consent-history persistence;
- account/user repositories and principal mapping;
- DB/cache implementations of Epicrypt stores;
- backend transactions/locking;
- sessions/cookies;
- application permission policy;
- rate limiting/audit/telemetry;
- environment/config/file loading;
- deployment key locations;
- tenant/client administration outside protocol fields.

A framework may adapt transport and persistence but must not reimplement PKCE, token claims, authorization-code semantics, refresh reuse detection, OIDC nonce/hash rules, access-token verification, DPoP, or PAT ability semantics.

---

## 2. Authentication paths and wire profiles

### OAuth 2.1

Required grants:

- Authorization Code + PKCE S256;
- Client Credentials;
- Refresh Token.

Excluded from 3.0:

- password grant;
- implicit grant;
- PKCE `plain`;
- query-string bearer tokens;
- partial/wildcard redirect matching.

### OpenID Connect 1.0

Authorization Code flow only, activated by `openid`; nonce/max_age/auth_time/acr/amr, signed ID Token, `sub`/`aud`/`azp`, `at_hash`/`c_hash`, UserInfo, and discovery. Optional ID-token encryption only after independent interoperability passes.

### Generic personal/API token

Framework-neutral Sanctum-style semantics: issue/list/verify/revoke/revoke-all, bounded exact abilities, optional expiry, stateful `jti` revocation, optional bounded last-used capability, raw JWT returned only at issue.

### Wire profiles

| Credential | Representation | Authoritative state |
| --- | --- | --- |
| OAuth access token | RFC 9068 signed JWT, `typ=at+jwt` | optional/required status policy |
| OAuth authorization code | short-lived compact JWE | mandatory exact-state atomic consume by `jti` |
| OAuth refresh token | compact JWE | family/token history, rotation/reuse |
| OIDC ID Token | signed JWT; optional JWE | normally stateless after issue |
| DPoP proof | signed JWT | replay store |
| OAuth client assertion | signed JWT | replay store + registered client key policy |
| Personal/API token | signed JWT, `typ=pat+jwt` | active/revoked record by `jti` |
| existing `PurposeToken` | existing signed-payload family | unchanged/non-interchangeable |

Cross-token substitution is rejected by `typ`, issuer/audience, dedicated key purpose, algorithm policy, required claims, and token-specific use markers.

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

- OAuth 2.1 `draft-ietf-oauth-v2-1-16` (published 2026-09-03); release review completed against the current draft;
- RFC 9700 Security BCP;
- RFC 7636 PKCE, S256-only Epicrypt profile;
- RFC 8414 metadata;
- RFC 9207 authorization-server issuer identification;
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

## 4. 3.0 API policy

Until 3.0 release:

1. clean final API beats source/API compatibility;
2. remove superseded unreleased symbols instead of adding shims;
3. do not keep dual auth credential formats merely for intermediate 3.0 commits;
4. keep the public API inventory synchronized after every public batch;
5. durable frozen cryptographic formats keep their independent compatibility lifecycle.

Example already applied: refresh-specific `Token\Opaque\RefreshToken*` was removed and replaced by `Auth\OAuth\RefreshToken*`; generic `Token\Opaque\OpaqueToken` remains.

---

## 5. Implemented authentication ledger

| Capability | State | Evidence |
| --- | --- | --- |
| auth token classes/media types + substitution policy | Complete | `2b9c18e7` |
| auth-specific KeyRing purposes + verifier binding | Complete | `0b0a9d7b` |
| RFC 9068 access-token profile audit/hardening | Complete | baseline + `2b9c18e7`, `0b0a9d7b` |
| authorization-code JWE artifact | Complete | `400497b3` |
| refresh-token JWE artifact | Complete | `c1b30119` |
| refresh authoritative lifecycle + store conformance | Complete | `168c7b3e` |
| legacy refresh-specific opaque API removal | Complete | `168c7b3e` |
| shared OAuth/OIDC/PAT hard bounds | Complete | `2b9c1c02` |
| authorization-code exact-state atomic consume | Complete | `8326444e` |
| OAuth client model/store | Complete | `d2ff4c81` |
| client-secret + strict `private_key_jwt` + replay | Complete | `5c01d1bb` |
| authorization/access-status/PAT state contracts | Complete | `143b1c21` |
| authorization request/result/error DTOs + endpoint capability catalog | Complete | `ad14609c` |
| authorization scope→audience resolution + non-empty resource binding | Complete | `5384f694` |
| typed authentication/authorization-decision interaction model | Complete | `530e379d` |
| approved authorization → JOSE code issue/store integration | Complete | `530e379d` |
| JOSE code decrypt/binding/authoritative consume integration | Complete | `530e379d` |
| authorization response/denial hardening + RFC 9207 `iss` response parameter | Complete | `5f1fa6fc` |
| authorization RFC 9700-focused negative vectors | Complete | `5f1fa6fc` |

### Store/concurrency decisions

- Raw authorization-code JWE is never persisted.
- `AuthorizationCodeStoreInterface` is authoritative for exact-state one-time consumption.
- Raw refresh JWE is never persisted.
- Refresh consumed ancestry remains retained through authorization lifetime for family-wide reuse detection.
- `OAuthAuthorizationStoreInterface` owns approved authorization active/revoked state.
- `OAuthAccessTokenStatusStoreInterface` is optional authoritative JWT `jti` status for immediate access-token revocation deployments.
- `PersonalAccessTokenStoreInterface` owns metadata-only PAT state; raw PAT JWTs are never persisted.
- Client-assertion and DPoP replay reuse `JwtReplayStoreInterface`; no OAuth-specific duplicate replay store is added.
- Consent-history persistence is application policy; Epicrypt stores the resulting approved authorization state only.
- Security-sensitive active/revoked reads must not be served from stale ordinary caches after revocation/disablement commits.

### Authorization-core decisions

- OAuth clients require at least one registered resource audience because every supported Epicrypt OAuth grant ultimately issues an RFC 9068 access token.
- A single registered audience can be resolved by `OAuthSingleAudienceResolver`.
- Multi-resource clients require an application-supplied `OAuthAuthorizationAudienceResolverInterface`.
- Resolver output is bounded, non-empty, unique, and must be a subset of client registration.
- Unknown/disabled clients and redirect mismatches never produce a redirect target.
- An omitted `redirect_uri` is accepted only when exactly one redirect is registered.
- `response_type=code` and PKCE S256 are mandatory.
- Malformed/duplicate singleton parameters fail rather than being silently normalized.
- Wrong client/redirect/PKCE attempts do not consume an authorization code.
- Successful authorization responses expose `code`, RFC 9207 `iss`, and optional `state`.
- User denial is represented as safe `access_denied` from an already validated authorization interaction.

---

## 6. Persistence/concurrency rules

Epicrypt ships no production DB/ORM/SQL/Redis/CacheLayer implementation for auth stores. Test-only stores live under `tests/`.

Every public store contract documents uniqueness, atomic operations, conflicts, expiry, idempotency, revocation, stale-read sensitivity, and multi-process consistency.

Critical atomic boundaries:

- authorization-code consume;
- refresh consume/replace/reuse detection;
- refresh family revoke;
- DPoP/client-assertion replay claim;
- PAT revoke/revoke-all versus verification/issue;
- access-token status lookup when authoritative;
- authorization revocation versus code/token issuance.

Cross-store operations that cannot be made globally atomic by Epicrypt must preserve fail-closed ordering and document adapter transaction requirements.

---

## 7. Test/interoperability/security gates

Required coverage includes:

- token-class substitution and wrong issuer/audience/key purpose/algorithm;
- active/fallback key rotation;
- malformed/oversized auth and JOSE input;
- duplicate OAuth parameters;
- PKCE/exact redirect/safe redirect errors;
- authorization-code replay and concurrent consume;
- public/confidential client-auth rules and assertion replay;
- Client Credentials;
- refresh rotation/reuse/concurrency/family revocation;
- RFC 9068 access validation;
- revocation/introspection;
- RFC 9700 negative vectors;
- OIDC nonce/azp/auth_time/max_age/acr/amr/hash/sub/UserInfo/discovery;
- PAT abilities/expiry/revoke/revoke-all/concurrency/Fiber/persistent worker;
- independent JOSE/OAuth/OIDC vectors where feasible.

Mutation shards to execute during release hardening:

```text
oauth-authorization
oauth-token-grants
oauth-refresh-revocation
oauth-client-auth
oidc-provider
personal-access-token
```

Release QA: PHP 8.4/8.5 lowest/stable, analyzers/PHPForge, dependency audit, no secret-bearing diagnostics, complexity caps, no global mutable request/trust state, and no framework/DB production dependency.

Performance attribution separately measures access-token issue/verify, code JWE issue/consume, refresh JWE+rotation, DPoP, ID Token, PAT store validation, active/fallback key verification, and persistent-worker memory.

---

## 8. Documentation deliverables

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

## 9. Implementation phases/checklist

### Phase A — Epicrypt rebaseline/API discipline

- [x] Capture regression/scope-extension baselines and preserve prior green release matrix. (`cca7e5a9`, `0ec87442`)
- [x] Inventory current JWT/JOSE/OIDC/DPoP/refresh primitives. (`8235274b` planning baseline)
- [x] Create Epicrypt 3 public API inventory.
- [x] Establish no-source/API-BC-before-3.0 rule while preserving frozen persisted formats. (`0aff2ae5`)
- [ ] Freeze the synchronized public API inventory at release. (inventory kept current during implementation)

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
- [x] Keep consent persistence application-owned; Epicrypt stores approved authorization state only. (`143b1c21`)
- [x] Authorization request/result/error DTOs. (`ad14609c`, `5f1fa6fc`)
- [x] Endpoint capability catalog with no route registration. (`ad14609c`)
- [x] Test-only client/refresh/code/authorization/access-status/PAT in-memory stores. (`d2ff4c81`, `168c7b3e`, `8326444e`, `143b1c21`)
- [x] Add token/revocation/introspection/OIDC/PAT endpoint-specific DTOs in their implementation phases. (`5b1ed2a5`, `2a28096f`)
- [ ] Add reusable fault/concurrency fixtures required by the final mutation/concurrency hardening pass. (Phase H)

### Phase D — OAuth authorization core — COMPLETE

- [x] Independent authorization request model/validator. (`ad14609c`)
- [x] Bounded duplicate-safe parameter envelope. (`ad14609c`, `5f1fa6fc`)
- [x] Exact redirect + `response_type=code` + mandatory PKCE S256. (`ad14609c`, `5f1fa6fc`)
- [x] Client grant + requested-scope subset validation. (`ad14609c`)
- [x] Scope→audience resolution hook and final audience binding. (`5384f694`)
- [x] Require non-empty registered resource audience(s). (`5384f694`)
- [x] Typed subject-authentication / authorization-decision interaction model. (`530e379d`)
- [x] Approval scope narrowing + authorization lifetime/authentication context. (`530e379d`)
- [x] Authorization-code authoritative one-time consume primitive. (`8326444e`)
- [x] Approved authorization + authorization-code JWE issue/store service. (`530e379d`)
- [x] JWE decrypt + client/redirect/PKCE + authoritative consume service. (`530e379d`)
- [x] Safe `access_denied` interaction result. (`5f1fa6fc`)
- [x] Authorization success/error response parameters with RFC 9207 `iss`. (`5f1fa6fc`)
- [x] OAuth authorization redirect safety. (`ad14609c`, `5f1fa6fc`)
- [x] RFC 9700-focused authorization negative vectors. (`5f1fa6fc`)
- [x] Move authorization mutation execution to Phase H release hardening; implementation vectors are complete. (plan decision)

### Phase E — OAuth token/core lifecycle — COMPLETE

- [x] Authorization Code token exchange. (`5b1ed2a5`; lifecycle coverage `b1ac1cb4`)
- [x] Client Credentials. (`5b1ed2a5`; lifecycle coverage `b1ac1cb4`)
- [x] Refresh-token rotation/reuse state machine. (`168c7b3e`)
- [x] Integrate refresh grant into OAuth token endpoint/result model. (`5b1ed2a5`)
- [x] Access-token issuance/validation service over RFC 9068 profile. (`5b1ed2a5`)
- [x] Optional authoritative access-token-status integration. (`5b1ed2a5`)
- [x] Revocation (RFC 7009). (`5b1ed2a5`)
- [x] Introspection (RFC 7662). (`5b1ed2a5`)
- [x] Authorization-server metadata (RFC 8414 + current OAuth 2.1 capability set). (`5b1ed2a5`)
- [x] Auth-scoped JWKS publication. (`5b1ed2a5`)
- [x] DPoP issuance/resource integration. (`5b1ed2a5`)
- [x] Token/revocation/introspection negative lifecycle vectors. (`b1ac1cb4`, `5b1ed2a5`)
- [x] Phase E plan/API inventory synchronization. (this completeness pass)

### Phase F — OpenID Connect provider — COMPLETE (3.0 required scope)

- [x] OIDC request extensions/`openid` activation. (`f187a02b`, `5b1ed2a5`)
- [x] nonce/prompt/max_age/acr interaction requirements. (`f187a02b`, `5b1ed2a5`)
- [x] ID Token issuer paired with hardened validator. (`5b1ed2a5`)
- [x] subject identifier provider contract. (`5b1ed2a5`)
- [x] UserInfo claims provider/projection. (`5b1ed2a5`)
- [x] discovery metadata. (`5b1ed2a5`)
- [x] Defer optional encrypted ID Token until independent encryption interoperability is intentionally added; it is not required for Epicrypt 3.0. (scope decision)
- [x] OIDC provider/negative vectors for the supported Authorization Code profile. (`5b1ed2a5`)
- [x] Phase F plan/API inventory synchronization. (this completeness pass)

### Phase G — generic personal/API tokens — COMPLETE (implementation)

- [x] Final public manager/policy/abilities API. (`2a28096f`)
- [x] `pat+jwt` profile + key-purpose enforcement. (`2a28096f`)
- [x] issue/verify/list/revoke/revoke-all manager semantics. (`2a28096f`)
- [x] exact abilities + explicit wildcard policy. (`2a28096f`)
- [x] authoritative metadata store; raw JWT never persisted. (`143b1c21`, `2a28096f`)
- [x] optional last-used capability with bounded/coalesced writes. (`2a28096f`)
- [x] concurrency/Fiber/persistent-runtime functional coverage. (`2a28096f`)
- [x] negative vectors for audience/key-purpose/expiry/wildcard/revocation boundaries. (`2a28096f`)
- [ ] Dedicated PAT/auth performance and persistent-runtime memory evidence. (Phase H release hardening)
- [x] Phase G plan/API inventory synchronization. (this completeness pass)

### Phase H — Epicrypt release hardening — IN PROGRESS

- [x] Latest OAuth 2.1 draft/RFC delta review; baseline updated to `draft-ietf-oauth-v2-1-16`, including mandatory `iss` on redirectable authorization errors. (2026-09-09 completeness pass)
- [ ] OIDC Core/Discovery Errata 2 requirements matrix.
- [x] Pre-auth Epicrypt regression gates. (`Epicrypt 3 Phase A+B Gates` run `34383486509` green at `4a8213e1`.)
- [x] Independent JOSE interoperability gate. (`Security & Standards` run `34383486883`.)
- [x] AEGIS positive gate on libsodium 1.0.22. (`Security & Standards` run `34383486883`.)
- [x] Clean production install/platform-requirements gate. (`Security & Standards` run `34383486883`.)
- [ ] Canonical PHPForge QA cleanup and release matrix.
  - [x] Reproduce the canonical release-autofix scope in CI scratch: 74 Pint style changes plus Rector auth transformations. (`Epicrypt Auth Release Autofix` run `34383486512`.)
  - [ ] Commit the canonical Pint/Rector output to the branch.
  - [ ] Add the seven proven non-secret `SensitiveParameterTest` allowlist entries for PAT `tokenId` and JWT-policy `tokenClass` parameters.
  - [ ] Resolve the seven expected PHPCS unused-interface/callback parameter warnings without weakening public contracts.
  - [ ] Re-run PHP 8.4/8.5 × prefer-lowest/prefer-stable QA after cleanup.
  - [ ] Re-run PHP 8.4/8.5 analyzers after cleanup.
- [ ] Execute `oauth-authorization` mutation shard.
- [ ] Execute remaining OAuth/OIDC/PAT mutation shards.
  - [ ] `oauth-token-grants`
  - [ ] `oauth-refresh-revocation`
  - [ ] `oauth-client-auth`
  - [ ] `oidc-provider`
  - [ ] `personal-access-token`
- [ ] Close the remaining `remote-jose` mutation failure from `Security & Standards` run `34383486883`.
- [ ] Dependency/security audit and complete `Security & Standards` release gate. (JOSE interoperability, AEGIS, clean install, and all non-remote-JOSE legacy mutation shards are already green; QA/analyzers and `remote-jose` remain red.)
- [ ] Independent OAuth/OIDC interoperability vectors beyond the already-green JOSE interoperability job.
- [ ] Performance/persistent-runtime memory checks.
- [ ] Complete docs/migration/API inventory.
- [ ] Remove obsolete unreleased compatibility surface and temporary release-autofix tooling after the ordinary release matrix is green.
- [ ] Freeze final public API inventory.
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

## 10. Immediate next batch

**Phase H only — Epicrypt 3.0 release hardening.**

1. [ ] Close the canonical PHPForge QA cleanup on the completed A–G implementation.
   - [x] Confirm the release-autofix workflow reproduces the 74 Pint style changes and Rector auth transforms. (`34383486512`)
   - [ ] Commit canonical Pint/Rector output.
   - [ ] Correct the seven `SensitiveParameterTest` false positives with explicit non-secret allowlist entries.
   - [ ] Resolve the seven PHPCS unused-interface/callback parameter warnings without changing contract semantics.
   - [ ] Re-run PHP 8.4/8.5 stable/lowest QA and analyzers until green.
2. [ ] Close the remaining `remote-jose` mutation failure, then require the ordinary `Security & Standards` workflow to be green.
3. [ ] Add reusable fault/concurrency fixtures needed by the final authorization/refresh/PAT mutation and concurrency shards.
4. [ ] Run `oauth-authorization`, then the remaining bounded auth mutation shards: `oauth-token-grants`, `oauth-refresh-revocation`, `oauth-client-auth`, `oidc-provider`, `personal-access-token`.
5. [ ] Add/finish deterministic parser fuzz/property coverage for authorization requests, client assertions, auth-code/refresh JWE claims, DPoP, ID-token verification inputs, and PAT claims.
6. [ ] Complete the OIDC Core/Discovery Errata 2 requirements matrix and standards/exclusions documentation.
7. [ ] Run independent OAuth/OIDC interoperability vectors plus auth/PAT performance and persistent-runtime memory attribution.
8. [ ] Finish docs, migration notes, and the public API inventory; remove temporary release-autofix tooling and obsolete unreleased surfaces.
9. [ ] Freeze the final public API inventory and record the exact release-ready SHA only after all Epicrypt gates are green.
10. [ ] Release Epicrypt 3.0; only then resume Foundation adoption.

---

## 11. Final target

Epicrypt 3 is complete when a framework implements only transport/application/persistence adapters and receives secure OAuth 2.1, OIDC 1.0, and generic personal/API token paths from Epicrypt without reimplementing protocol cryptography or authoritative auth state-machine semantics.