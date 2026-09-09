# Epicrypt 3 — Final Authentication Protocol Development Plan

**Status:** Active implementation plan  
**Target:** Epicrypt 3.0  
**Branch:** `epicrypt-3/architecture-plan`  
**Regression baseline:** `cca7e5a93f8b5f37329053b448fbce91e9496262`  
**Auth scope-extension baseline:** `0ec8744232f1c67f776a8fbd5414eee7a01369ab`  
**Priority:** standards correctness → security → deterministic state semantics → framework neutrality → performance → ergonomics

> Epicrypt 3.0 has not been released. Until the 3.0 release is cut, **source/API backward compatibility is not a design constraint**. Prefer the clean final 3.0 API and remove superseded unreleased surfaces rather than carrying aliases, wrappers or parallel implementations.
>
> Persisted cryptographic compatibility is separate. Frozen Epicrypt 2.x `ep2` string/file formats and signed-payload v2 fixtures remain supported where the existing 3.0 work established them as durable format contracts.
>
> Epicrypt 3 is implemented and released **independently first**. Foundation is reference material only during this work. Foundation extraction, adapters, persistence migration and integration start after Epicrypt 3.0 is released and are not release blockers for Epicrypt.

---

## 1. Final product boundary

Epicrypt 3 is a reusable, transport-neutral authentication/security protocol core.

### Epicrypt owns

- JWT/JWS/JWE/JWK/JWKS primitives and policy;
- auth-token class separation and key-purpose isolation;
- OAuth 2.1 authorization and token protocol mechanics;
- framework-neutral OAuth client model and client authentication;
- Authorization Code + mandatory PKCE S256;
- Client Credentials;
- refresh rotation/reuse/revocation state machine;
- RFC 9068 JWT access tokens;
- revocation/introspection/authorization-server metadata;
- DPoP proof validation and access-token binding;
- OpenID Connect request, ID-token, UserInfo and discovery mechanics;
- generic personal/API token issue, abilities, verification and revocation;
- public persistence contracts for one-time/replay/revocation state;
- transport-neutral protocol DTOs/results/errors and endpoint capability metadata.

### Framework/application owns

- routes and HTTP adaptation;
- login/authentication UI;
- consent UI/application decision;
- account/user repositories and principal mapping;
- DB/cache implementations of Epicrypt stores;
- backend transactions/locking;
- sessions/cookies;
- application authorization/permission mapping;
- rate limiting/audit/telemetry;
- environment/config/file loading;
- deployment key locations and tenant administration policy.

A framework may adapt transport and persistence but must not reimplement PKCE, token claims, refresh reuse detection, OIDC nonce/hash rules, access-token verification, DPoP or PAT ability semantics.

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

Framework-neutral Sanctum-style management semantics: issue/list/verify/revoke/revoke-all, bounded exact abilities, optional expiry, stateful `jti` revocation, optional bounded last-used capability, raw JWT returned only at issue.

### Wire profiles

| Credential | Representation | Authoritative state |
| --- | --- | --- |
| OAuth access token | RFC 9068 signed JWT, `typ=at+jwt` | optional/required status policy |
| OAuth authorization code | short-lived compact JWE | mandatory atomic consume by `jti` |
| OAuth refresh token | compact JWE | family/token history, rotation/reuse |
| OIDC ID Token | signed JWT; optional JWE | normally stateless after issue |
| DPoP proof | signed JWT | replay store |
| OAuth client assertion | signed JWT | replay store + client key policy |
| Personal/API token | signed JWT, `typ=pat+jwt` | active/revoked record by `jti` |
| existing `PurposeToken` | existing signed-payload family | unchanged/non-interchangeable |

Cross-token substitution is rejected by `typ`, issuer/audience, dedicated key purpose, allowed algorithms, required claims and token-specific use markers.

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
3. no dual auth credential formats merely to preserve intermediate development commits;
4. public API inventory records every intentional public change;
5. durable frozen cryptographic formats keep their independent compatibility lifecycle.

Current example: refresh-specific `Token\Opaque\RefreshToken*` was removed and replaced by `Auth\OAuth\RefreshToken*`; generic `Token\Opaque\OpaqueToken` remains.

---

## 5. Completed authentication substrate ledger

| Capability | State | Evidence |
| --- | --- | --- |
| auth token classes/media types | Complete | `2b9c18e7` |
| token-class substitution policy/tests | Complete | `2b9c18e7` |
| auth-specific KeyRing purposes | Complete | `0b0a9d7b` |
| OAuth/OIDC JWT key-purpose enforcement | Complete | `0b0a9d7b` |
| RFC 9068 access-token profile audit/hardening | Complete | baseline + `2b9c18e7`, `0b0a9d7b` |
| authorization-code JWE artifact | Complete | `400497b3` |
| refresh-token JWE artifact | Complete | `c1b30119` |
| refresh authoritative family lifecycle | Complete | `168c7b3e` |
| legacy refresh-specific `Token\Opaque` API removal | Complete | `168c7b3e` |
| refresh store conformance suite | Complete | `168c7b3e` |
| centralized OAuth/OIDC/PAT hard bounds | Complete | `2b9c1c02` |
| authorization-code authoritative consume contract | Complete | `8326444e` |
| authorization-code store conformance suite | Complete | `8326444e` |

### Central hard-limit rule

`Auth\Internal\AuthProtocolPolicy` owns hard auth ceilings for parameters, identifiers, redirect/nonce, PKCE, scopes, audiences, OIDC authentication methods, PAT abilities/listing and auth claim limits. JOSE remains the lower-level owner of serialization/depth limits; the auth policy references those caps rather than making JOSE depend on `Auth`. Future public server/client policy may only make these limits stricter, never wider.

### Authorization-code store rule

The store persists no raw JWE. `AuthorizationCodeRecord` stores code `jti`, authorization ID, expiry and SHA-256 digest of the canonical authenticated claim set. `AuthorizationCodeStoreInterface::consume()` atomically compares exact state and returns `CONSUMED`, `REPLAYED`, `EXPIRED` or `INVALID`. Consumed records remain through expiry; find-then-delete is not a valid implementation.

### Refresh store rule

The store persists no raw JWE and no digest of the raw credential. The authenticated refresh JWE supplies `jti`, family and authorization state; `RefreshTokenStoreInterface` atomically consumes current and persists the exact successor state committed by the newly issued JWE. Consumed history is retained through authorization lifetime so ancestor reuse can revoke the family.

---

## 6. Remaining architecture target

### OAuth client/authentication

Bounded client record:

- client ID, public/confidential type, enabled state;
- exact redirect URIs;
- allowed grants/scopes/audiences;
- allowed client-auth methods;
- secret-hash metadata where used;
- JWK/JWKS material/reference for `private_key_jwt`;
- OIDC ID-token policy metadata;
- bounded token lifetime overrides.

3.0 client auth: public/no-auth where permitted, `client_secret_basic`, optional `client_secret_post`, `private_key_jwt`. Multiple simultaneous methods fail; raw secrets are non-recoverable; assertion `iss/sub/aud/exp/iat/jti` and replay are authoritative and bounded.

### Transport-neutral protocol operations

Target service family:

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

No framework request/response type or route registration in core.

### Authorization endpoint

- exact redirect matching;
- `response_type=code` only;
- PKCE S256 mandatory;
- bounded/duplicate-safe parameters;
- client/grant/scope/audience validation;
- safe redirect-error rules;
- authentication/consent represented as typed interaction requirements;
- JOSE code issue + atomic store create/consume.

### Token endpoint

Typed handlers for Authorization Code, Client Credentials and Refresh Token. Authorization-code exchange validates exact client/redirect/PKCE before atomic consume. Refresh handler uses the completed JOSE lifecycle. Protocol boundary maps expected credential failures safely to OAuth errors without leaking internal lifecycle detail.

### Access token/revocation/introspection/metadata

RFC 9068 issuance/verification service, optional authoritative `jti` status, RFC 7009/7662 semantics, capability-accurate metadata, JWKS scoped to auth signing purposes, DPoP `cnf.jkt` integration.

### OIDC provider

`openid` activation, interaction requirements, ID Token issuer paired with existing validator, subject-ID provider contract, UserInfo claims provider/projection and discovery. Application account IDs are not assumed to be public OIDC `sub` values.

### Personal/API token core

Suggested public family:

```text
PersonalAccessTokenManager
PersonalAccessTokenIssue
PersonalAccessTokenResult
PersonalAccessTokenRecord
PersonalAccessTokenStoreInterface
PersonalAccessTokenPolicy
PersonalAccessTokenAbilities
```

`pat+jwt`, exact abilities, explicit `*` policy, stateful immediate revocation, metadata-only listing, optional last-used capability without forced writes.

---

## 7. Persistence/concurrency rules

Epicrypt ships no production DB/ORM/SQL/Redis/CacheLayer implementation for auth stores. Test-only stores live under `tests/`.

Every public store contract documents uniqueness, atomic operations, conflicts, expiry, idempotency, revocation, stale-read sensitivity and multi-process consistency.

Critical atomic boundaries:

- authorization-code consume;
- refresh consume/replace/reuse detection;
- refresh family revoke;
- DPoP/client-assertion replay claim;
- PAT revoke/revoke-all versus verification;
- access-token status lookup when authoritative.

---

## 8. Test/interoperability/security gates

Required coverage includes:

- token-class substitution and wrong issuer/audience/key purpose/algorithm;
- active/fallback key rotation;
- malformed/oversized auth and JOSE input;
- PKCE, exact redirect and code replay/concurrent consume;
- public/confidential client-auth rules and assertion replay;
- Client Credentials;
- refresh rotation/reuse/concurrency/family revocation;
- RFC 9068 access validation;
- revocation/introspection and RFC 9700 negatives;
- OIDC nonce/azp/auth_time/max_age/acr/amr/hash/sub/UserInfo/discovery;
- PAT abilities/expiry/revoke/revoke-all/concurrency/Fiber/persistent worker;
- independent JOSE/OAuth/OIDC vectors where feasible.

Dedicated mutation shards:

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

- [x] Capture regression/scope-extension baselines and keep prior green release matrix as non-regression floor. (`cca7e5a9`, `0ec87442`)
- [x] Inventory current Epicrypt JWT/JOSE/OIDC/DPoP/refresh primitives. (`8235274b` planning baseline)
- [x] Create Epicrypt 3 public API inventory.
- [x] Establish no-source/API-BC-before-3.0-release rule while preserving explicitly frozen persisted formats. (`0aff2ae5`)
- [ ] Keep public API inventory synchronized and freeze it at release.

### Phase B — auth-token/JOSE substrate

- [x] Explicit auth token classes/media types and substitution policy. (`2b9c18e7`)
- [x] RFC 9068 profile audit/hardening. (baseline + `2b9c18e7`, `0b0a9d7b`)
- [x] Authorization-code JWE profile. (`400497b3`)
- [x] Refresh-token JWE profile. (`c1b30119`)
- [x] Refresh authoritative lifecycle. (`168c7b3e`)
- [x] Remove superseded opaque refresh API. (`168c7b3e`)
- [x] Auth key-purpose isolation. (`0b0a9d7b`)
- [x] Token/artifact substitution/security-negative tests. (`2b9c18e7`, `0b0a9d7b`, `400497b3`, `c1b30119`, `168c7b3e`)
- [x] Centralize shared OAuth/OIDC/PAT hard bounds. (`2b9c1c02`)

### Phase C — client/store/endpoint contracts

- [ ] Framework-neutral OAuth client model/policy.
- [ ] Client-secret verification and `private_key_jwt` validation/replay contract.
- [x] Refresh-token authoritative store + exact replacement atomicity/conformance. (`168c7b3e`)
- [x] Authorization-code authoritative store + exact-state atomic consume/conformance. (`8326444e`)
- [ ] Authorization, client, access-token-status, consent/replay and PAT store contracts.
- [ ] Protocol request/result/error DTOs.
- [ ] Endpoint capability catalog with no route registration.
- [x] Test-only refresh/code in-memory + reusable conformance stores. (`168c7b3e`, `8326444e`)
- [ ] Remaining test-only fault/in-memory stores.

### Phase D — OAuth authorization core

- [ ] Independent Epicrypt authorization request model/validator.
- [ ] Exact redirect + `response_type=code` + mandatory PKCE S256.
- [ ] Scope/audience resolution hooks.
- [ ] Authentication/consent interaction model.
- [x] Authorization-code authoritative one-time consume primitive. (`8326444e`)
- [ ] Integrate authorization-code JWE issue/store/consume service.
- [ ] OAuth errors/redirect safety.
- [ ] RFC 9700 authorization negative vectors.

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

- [ ] Final public naming/API.
- [ ] `pat+jwt` profile + key-purpose enforcement.
- [ ] issue/verify/list/revoke/revoke-all.
- [ ] exact abilities + explicit wildcard policy.
- [ ] authoritative store; raw JWT never persisted.
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
- [ ] Remove any obsolete unreleased compatibility surface.
- [ ] Mark exact final SHA release-ready only after complete Epicrypt gates are green.
- [ ] Release Epicrypt 3.0.

### Deferred after 3.0 release — Foundation adoption

**Not an Epicrypt 3 release gate.**

- [ ] Rescan Foundation auth/OAuth source/contracts/stores/routes/schema/tests against released Epicrypt 3.
- [ ] Produce move/keep/replace inventory.
- [ ] Freeze Foundation migration vectors where real persisted state requires it.
- [ ] Add Foundation DBLayer implementations of released store contracts.
- [ ] Replace Foundation protocol mechanics with Epicrypt services.
- [ ] Keep Foundation transport/login/consent/audit/rate-limit/config/principal/application policy only.
- [ ] Remove obsolete Foundation auth/Epicrypt indirection.
- [ ] Migrate existing persisted Foundation auth state only where evidence requires it.
- [ ] Close Foundation Epicrypt/Pathwise and Epicrypt-dependent OTP/Passkey acceptance work.
- [ ] Run Foundation PHP 8.4/8.5 composition gates and update Foundation plan/docs.

---

## 11. Immediate next batch

**Epicrypt only.**

1. Implement the framework-neutral OAuth client model and client store contract.
2. Add bounded client-secret authentication primitives and `private_key_jwt` assertion/replay contracts.
3. Define remaining authorization/status/replay/PAT store contracts needed by endpoint state machines.
4. Then build the authorization request/interaction DTO layer and integrate JOSE code issue + authoritative consume.
5. Update this checklist/API inventory after each implementation commit; full CI/release gates remain unchecked until independently green.

---

## 12. Final target

Epicrypt 3 is complete when a framework implements only transport/application/persistence adapters and receives the three secure paths from Epicrypt: OAuth 2.1, OIDC 1.0 and generic personal/API tokens. No framework should need to reimplement protocol cryptography or authoritative auth state-machine semantics.
