# Epicrypt 3 — Final Authentication Protocol Development Plan

**Status:** Active scope-extension plan  
**Target:** Epicrypt 3.0  
**Branch:** `epicrypt-3/architecture-plan`  
**Regression baseline:** `cca7e5a93f8b5f37329053b448fbce91e9496262`  
**Scope-extension baseline:** `0ec8744232f1c67f776a8fbd5414eee7a01369ab`  
**Priority:** standards correctness → security → persisted-token compatibility/migration → deterministic state semantics → framework neutrality → performance → ergonomics

> Epicrypt 3 had reached a green release-readiness baseline before this scope extension. That baseline remains a non-regression floor, not the release endpoint. Epicrypt 3 will now become the reusable transport-neutral authentication protocol core for three first-class authentication paths: **OAuth 2.1**, **OpenID Connect 1.0**, and a **Sanctum-style generic personal/API token system**.
>
> Foundation already contains a substantial OAuth 2.1 authorization-server implementation. This plan is therefore **extraction-driven**, not a rewrite-from-zero exercise: standards-correct protocol mechanics move to Epicrypt; framework/HTTP/database/application policy stays in Foundation.

---

## 1. Final product boundary

Epicrypt 3 owns reusable security/authentication protocol mechanics. It does **not** become an HTTP framework, ORM, database library, session framework, account system, consent UI, or application authorization system.

### Epicrypt owns

- JWT/JWS/JWE/JWK/JWKS primitives and policy;
- token-class domain separation and key selection/rotation;
- OAuth 2.1 authorization request validation and protocol state machine;
- OAuth client model and protocol-level client authentication;
- Authorization Code + PKCE semantics;
- Client Credentials semantics;
- Refresh Token rotation/reuse/revocation semantics;
- JWT access-token issuance and resource-token validation;
- OAuth revocation/introspection protocol semantics;
- OAuth authorization-server metadata structures;
- DPoP proof validation/binding;
- OpenID Connect request/ID-token/UserInfo/discovery mechanics;
- generic first-party personal/API token issuance, abilities, verification and revocation semantics;
- public persistence contracts required to make one-time use/revocation/rotation authoritative;
- transport-neutral endpoint/request/response DTOs and error models;
- endpoint capability/catalog metadata that frameworks can map to routes.

### Framework/application owns

- route paths and HTTP router registration;
- HTTP request/body/header adaptation and response emission;
- login/authentication UI and acquisition of the authenticated subject;
- consent screen/UI and application decision;
- account/user repositories and application principal mapping;
- database/cache implementations of Epicrypt public store interfaces;
- transactions appropriate to the chosen persistence backend;
- sessions/cookies;
- application permission mapping and business authorization;
- rate limiting, audit/observability and telemetry;
- configuration/env/file loading;
- tenant/application-specific client administration policy;
- deployment key/secret location policy.

### Hard rule

A framework adapter may adapt transport and persistence, but must not reimplement PKCE, grant validation, token claims, refresh reuse detection, OIDC nonce/hash rules, JWT access-token validation, DPoP, or personal-token ability semantics.

---

## 2. Three first-class authentication paths

Epicrypt 3 must expose three separate but interoperable authentication paths over one shared JOSE substrate.

```text
                         Epicrypt JOSE / Keys
                    JWT + JWS + JWE + JWK + JWKS
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
        OAuth 2.1             OIDC 1.0          Generic API/PAT
      protocol core        identity layer       Sanctum-style core
             │                    │                    │
       at+jwt / JWE          ID Token JWT             pat+jwt
       refresh JWE/JWT       UserInfo claims      abilities + jti
       auth-code JWE              │             stateful revocation
             └────────────────────┴────────────────────┘
                                  │
                    public persistence contracts
                       (no DB implementation)
```

### 2.1 OAuth 2.1 path

Primary use: delegated API authorization and machine-to-machine authorization.

Required grants for 3.0:

- Authorization Code + mandatory PKCE S256;
- Client Credentials;
- Refresh Token.

Explicitly excluded from new implementation:

- Resource Owner Password Credentials grant;
- Implicit grant / access tokens in authorization responses;
- PKCE `plain`;
- bearer credentials in query strings;
- wildcard/partial redirect URI matching.

### 2.2 OpenID Connect path

OIDC is implemented as an identity layer on the OAuth core, not a separate authorization engine.

Required 3.0 profile:

- Authorization Code flow only;
- `openid` scope activation;
- nonce handling;
- ID Token issuance/validation;
- `sub`, `aud`, `azp`, `auth_time`, `acr`, `amr` support;
- `at_hash` and `c_hash` where applicable;
- `max_age` and authentication requirement modeling;
- UserInfo claim projection;
- provider discovery metadata;
- static client metadata needed for ID-token signing/encryption policy;
- signed ID Tokens mandatory; encrypted ID Tokens optional when explicitly configured and interoperably tested.

OIDC implicit/hybrid flows are not added merely because OIDC Core describes them; the Epicrypt OIDC provider profile remains aligned with the safer OAuth 2.1 authorization-code path.

### 2.3 Sanctum-style generic personal/API token path

This is framework-neutral personal access token / first-party API token management. It must not depend on OAuth client/grant concepts.

Required semantics:

- issue a token to an application-defined subject;
- human-readable token name/label;
- bounded ability list (`*` allowed only as an explicit policy choice);
- optional expiration;
- JWT `jti` identity;
- list active token metadata through the store contract;
- verify token signature, class, subject, expiry and authoritative active record;
- `can()` / `cannot()` ability checks with exact matching by default;
- revoke one token;
- revoke all tokens for a subject;
- optional bounded last-used metadata update through a store capability/policy rather than mandatory write-on-every-request;
- raw token is returned only at issuance; stores never require raw JWT storage.

This path provides the convenience/security model people expect from Sanctum-style tokens without coupling Epicrypt to Laravel, Eloquent, cookies, middleware or routes.

---

## 3. JWT/JOSE-first token architecture

All three auth paths use JWT/JOSE-family credentials. Server-side state remains mandatory where protocol semantics require one-time use, revocation or replay/reuse detection; state is **not** an excuse to fall back to ad-hoc opaque token formats.

### 3.1 Token classes and wire profiles

| Credential | 3.0 representation | State requirement |
| --- | --- | --- |
| OAuth access token | RFC 9068-style signed JWT, `typ=at+jwt` | optional/required status lookup according to configured revocation policy |
| OAuth authorization code | short-lived encrypted JOSE artifact (JWE carrying bounded JWT-style claims) | mandatory atomic one-time consume by `jti`/code id |
| OAuth refresh token | confidentiality-preserving JWE/JWT-style artifact | mandatory refresh-family record, rotation and reuse detection |
| OIDC ID Token | signed JWT; optional JWE when explicitly configured | normally stateless after issuance; client/session policy remains outside |
| DPoP proof | signed JWT per RFC 9449 | replay store required |
| OAuth client assertion | signed JWT | replay/audience/time validation required |
| Generic personal/API token | signed JWT, private media type such as `pat+jwt` | mandatory active/revoked token record keyed by `jti` |
| existing Epicrypt `PurposeToken` | existing signed-payload family | unchanged; not interchangeable with OAuth/OIDC/PAT tokens |

### 3.2 Cross-token substitution must be impossible

Every verifier must bind at least:

- token class / `typ`;
- issuer where applicable;
- intended audience;
- key purpose;
- allowed algorithm family;
- required claims;
- token-specific purpose/use marker when a registered `typ` alone is insufficient.

An OAuth access token must fail as a personal token, ID Token, authorization code or refresh token. A personal token must fail as OAuth bearer authorization even if it uses the same JOSE algorithm.

### 3.3 Separate key purposes

Add/maintain explicit key domains instead of sharing one signing key implicitly:

```text
oauth.access-token.signing.v1
oauth.authorization-code.protection.v1
oauth.refresh-token.protection.v1
oidc.id-token.signing.v1
oidc.id-token.encryption.v1       # only when enabled
api.personal-token.signing.v1
```

Frameworks may deliberately map multiple domains to one external key only through explicit configuration; Epicrypt APIs must keep purposes distinct.

---

## 4. Standards baseline

### 4.1 OAuth

Implementation baseline at plan creation (2026-09-09):

- **OAuth 2.1:** `draft-ietf-oauth-v2-1-15` (2026-03-02), currently the latest revision; it expired on 2026-09-03 and remains work-in-progress.
- **OAuth Security BCP:** RFC 9700.
- **PKCE:** RFC 7636, S256 only for this profile.
- **Authorization Server Metadata:** RFC 8414.
- **Authorization Server Issuer Identification:** RFC 9207 where applicable.
- **Token Revocation:** RFC 7009.
- **Token Introspection:** RFC 7662.
- **JWT Profile for OAuth Access Tokens:** RFC 9068.
- **JWT client authentication:** RFC 7523 / assertion framework as applicable.
- **DPoP:** RFC 9449.

Before final release, re-check whether OAuth 2.1 draft-16 or an RFC has replaced draft-15 and perform a normative delta review. Do not advertise a finalized “OAuth 2.1 RFC compliant” claim while the specification remains an Internet-Draft.

### 4.2 OpenID Connect

Baseline:

- **OpenID Connect Core 1.0 incorporating Errata Set 2** (approved final/errata baseline, 2023-12-15);
- **OpenID Connect Discovery 1.0 incorporating Errata Set 2**;
- JWT/JWS/JWE/JWK/JWKS standards already used by Epicrypt.

Dynamic Client Registration, logout profiles and federation are not required for the first Epicrypt 3 provider core unless a concrete consumer requires them and independent interoperability fixtures are added.

---

## 5. Foundation extraction inventory

Foundation currently implements a large part of the target OAuth core under `src/Auth/OAuth` plus DBLayer/Epicrypt adapters. Extraction must classify each class as **move/refactor into Epicrypt**, **remain in Foundation**, or **replace with an Epicrypt public contract**.

### 5.1 Protocol mechanics to move/refactor into Epicrypt

Current Foundation examples include:

- `OAuthManager` orchestration of authorization validation, approval/code issue, exchange, revocation, introspection, metadata and JWKS;
- `AuthorizationRequestValidator` including exact redirect validation, response type, PKCE S256 and bounded state/scope/audience parsing;
- `AuthorizationCodeManager` and authorization-code issue/consume semantics;
- `OAuthTokenManager` grant dispatch for authorization-code/client-credentials/refresh, scope narrowing and token response semantics;
- `OAuthRefreshTokenCoordinator` rotation/reuse semantics;
- `OAuthRevocationManager` protocol behavior;
- `OAuthIntrospectionManager` protocol behavior;
- `OAuthClient`, grant/auth-method value objects and generic client validation;
- `OAuthScopeResolver` generic requested/allowed scope/audience selection;
- `AuthorizationServerMetadata` protocol metadata structure;
- generic OAuth protocol exceptions/error codes;
- access-token claims/profile and JWKS protocol mechanics.

These concepts become Epicrypt protocol/core classes, renamed where necessary to be framework-neutral.

### 5.2 Public contracts move to Epicrypt; implementations stay outside

Foundation DBLayer adapters currently implement client/authorization/code/refresh/revocation/consent stores. Epicrypt will define the authoritative interfaces and record/value objects; Foundation keeps DBLayer implementations.

Required Epicrypt store contracts include at least:

```text
OAuthClientStoreInterface
OAuthAuthorizationStoreInterface
OAuthAuthorizationCodeStoreInterface
OAuthRefreshTokenStoreInterface
OAuthAccessTokenStatusStoreInterface
OAuthConsentStoreInterface
OAuthReplayStoreInterface          # assertions/DPoP where appropriate
PersonalAccessTokenStoreInterface
```

Contracts must state atomicity/concurrency requirements explicitly. For example, authorization-code consume and refresh rotation/reuse detection cannot be modeled as a read followed by an unrelated delete/update.

### 5.3 Foundation-specific behavior that remains in Foundation

- DBLayer store implementations and schema/migrations;
- `OAuthAuditRecorder` and Foundation event taxonomy;
- route/controller registration and Webrick response construction;
- endpoint rate limits and CacheLayer store selection;
- application config/env/defaults and key-file locators;
- account/principal repositories;
- mapping OAuth scopes to Foundation permissions;
- consent UI and application authorization decision;
- application session/login behavior;
- CLI client administration commands (they may call Epicrypt core services);
- bearer principal adaptation into Foundation principal types;
- application authorization middleware.

### 5.4 Extraction compatibility rule

Do not port Foundation code blindly. Freeze the existing Foundation OAuth behavior first, compare it with the standards baseline, and preserve only standards-correct behavior. If Foundation behavior is non-compliant or over-coupled to application policy, fix it in Epicrypt and document the Foundation migration delta.

---

## 6. Public protocol surface — no routes, no database implementation

Epicrypt provides endpoint **operations**, not HTTP routes.

### 6.1 Transport-neutral endpoint services

Target public surface, naming subject to implementation review:

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

Each accepts typed input/context DTOs and returns typed protocol results/errors. No PSR-7/Webrick/Symfony/Laravel request or response type appears in the core signature.

Framework adapter example:

```text
HTTP request
  -> framework parses method/header/body/query
  -> Epicrypt request DTO
  -> Epicrypt endpoint service
  -> typed success/error result
  -> framework emits HTTP status/headers/body
```

### 6.2 Endpoint catalog

Provide endpoint capability metadata so a framework can register conventional routes without Epicrypt registering them itself. The catalog may describe semantic endpoint names, supported methods/content types and metadata keys, but **not force route paths**.

Typical adapter paths remain framework choices:

```text
/oauth/authorize
/oauth/token
/oauth/revoke
/oauth/introspect
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
/.well-known/jwks.json
/oauth/userinfo
```

### 6.3 Protocol error surface

Create a stable transport-neutral error model carrying only protocol-safe fields such as:

```text
error
error_description?      # bounded/safe, optional
error_uri?
state?                  # only when safe to echo
redirect_allowed
http_authentication_failure
```

Framework adapters decide actual HTTP status/header/body serialization. Raw secrets, tokens, assertions and backend exception text never appear in the public error.

---

## 7. Shared client model and authentication

### 7.1 Client registration model

Epicrypt defines a framework-neutral bounded client record containing protocol data only:

- client id;
- public/confidential type;
- enabled status;
- exact redirect URIs;
- allowed grants;
- allowed scopes and resource audiences;
- allowed client-authentication methods;
- secret hash metadata where symmetric client auth is used;
- client JWK/JWKS material/reference for `private_key_jwt`;
- OIDC metadata required for ID-token policy;
- token lifetime overrides only when bounded by server policy.

Display name, owner/team, billing, tenant administration and UI metadata remain application concerns unless a protocol field needs them.

### 7.2 Client authentication

Initial 3.0 support:

- no client authentication for public clients where permitted;
- `client_secret_basic`;
- `client_secret_post` only if explicitly enabled by server policy;
- `private_key_jwt`.

Rules:

- credentials supplied through two authentication methods simultaneously fail;
- raw client secrets are never recoverable from stores;
- client assertion `iss/sub/aud/exp/iat/jti` are bounded and verified;
- assertion replay protection uses an explicit store;
- algorithm/key selection is pinned by client policy; no untrusted `alg` expansion.

mTLS client authentication is a later extension unless a concrete consumer requires it for 3.0.

---

## 8. OAuth 2.1 authorization endpoint core

### 8.1 Authorization request validation

Move and harden Foundation's existing behavior:

- exact registered redirect URI matching;
- `response_type=code` only;
- mandatory PKCE S256;
- bounded `client_id`, `redirect_uri`, `state`, `scope`, `audience` and extension parameters;
- duplicate parameter rejection at adapter/parser boundary;
- enabled-client/grant validation;
- allowed-scope/audience selection;
- authorization-server issuer mix-up protection where applicable;
- no redirect on requests where redirect URI/client trust has not been established;
- stable protocol error model.

### 8.2 Authentication/consent interaction boundary

Epicrypt must not perform login or render consent. It returns a typed interaction requirement such as:

```text
AuthenticationRequired
ConsentRequired
AuthorizationReady
ProtocolFailure
```

Framework provides an `AuthenticatedSubject`/authorization decision back to Epicrypt containing only protocol-relevant state:

- stable subject id;
- authentication time;
- authentication methods (`amr`);
- authentication context (`acr`) when used;
- approved scopes/audiences;
- optional OIDC claim availability descriptor.

### 8.3 Authorization code

New codes are JOSE-based, confidentiality-preserving and short lived.

Required claims/state include at least:

- unique code id / `jti`;
- client id;
- subject/authorization id;
- exact redirect URI binding or stable digest thereof;
- PKCE challenge/method;
- scopes;
- audiences;
- issue/expiry time;
- nonce/OIDC transaction data when OIDC is active.

The code store is still mandatory for atomic one-time consume. A valid JWE with an already-consumed `jti` is invalid.

---

## 9. OAuth 2.1 token endpoint core

### 9.1 Grant dispatcher

Typed grant handlers rather than one growing conditional method:

```text
AuthorizationCodeGrant
ClientCredentialsGrant
RefreshTokenGrant
```

All grant handlers share bounded input parsing, client authentication, scope policy, error mapping and token issuer abstractions.

### 9.2 Authorization Code exchange

- authenticate/identify client according to client policy;
- atomically consume code;
- exact client + redirect binding;
- verify PKCE S256;
- verify authorization remains active according to store/application callback contract;
- issue access token;
- optionally issue refresh token according to authorization/client/server policy.

### 9.3 Client Credentials

- confidential/authenticated clients only;
- no human subject claim masquerading as a user;
- use a clear client subject convention/profile;
- scopes/audiences must be client/server allowed;
- no refresh token by default unless explicitly supported by a justified profile.

### 9.4 Refresh Token

New refresh tokens are JOSE-protected but stateful.

- signed/encrypted token binds family id, token id, client id, authorization/subject, scopes, audiences, issue/expiry time and optional sender constraint;
- store tracks authoritative family/token state;
- every successful use rotates to a new token;
- replay of an already-rotated token triggers the configured family compromise/revocation response;
- scope may only narrow;
- client/audience/sender binding cannot broaden;
- concurrent double-spend behavior is explicitly tested.

Reuse the security semantics already proven by Epicrypt's refresh-token work, but adapt the credential format to the new JWT/JOSE auth-token architecture rather than retaining an unrelated opaque auth path.

---

## 10. OAuth JWT access-token profile

### 10.1 Access-token claims

Use an RFC 9068-aligned profile with bounded claims, including as appropriate:

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

Additional private claims require an explicit namespace/policy and must not collide with registered claims.

### 10.2 Verification

Resource-token validation requires:

- `typ=at+jwt`;
- pinned allowed signature algorithms;
- trusted issuer;
- required audience;
- bounded time/leeway policy;
- client/scope shape validation;
- DPoP confirmation (`cnf`) when sender constrained;
- optional/required active-status or revocation-store lookup according to deployment policy.

Return a backend-neutral `OAuthAccessTokenPrincipal` / claims result that frameworks map into their own principal/account model.

### 10.3 Revocation and introspection

Revocation and introspection remain meaningful for JWT access tokens because Epicrypt exposes authoritative token-status contracts.

- access-token revocation keyed by `jti`/issuer/token class, never raw-token storage;
- refresh revocation targets token/family/authorization according to policy;
- RFC 7009 behavior must not leak token existence improperly;
- RFC 7662 result is derived from cryptographic validation plus authoritative status as configured;
- introspection client authorization is separate from resource-token validation.

---

## 11. OAuth metadata and JWKS

Epicrypt exposes typed authorization-server metadata and public JWKS structures.

Metadata includes only capabilities actually enabled by the composed server profile:

- issuer;
- authorization/token/revocation/introspection endpoints supplied by adapter configuration;
- JWKS URI supplied by adapter configuration;
- supported grants/response types;
- PKCE methods (`S256`);
- token endpoint auth methods;
- access-token signing algorithms;
- DPoP algorithms when enabled;
- scopes only if the application elects to publish them.

Epicrypt never invents deployment URLs. The framework supplies endpoint URIs and Epicrypt validates/serializes the metadata.

---

## 12. DPoP integration

Epicrypt already has DPoP verification primitives; integrate them into OAuth issuance/resource validation rather than maintaining a disconnected helper.

- validate proof `typ`, JWK, algorithm, `htm`, normalized `htu`, `iat`, `jti`;
- independent proof-age and future-skew bounds remain intact;
- replay store required;
- token endpoint binds issued access token using `cnf.jkt` when DPoP is accepted;
- resource validator requires matching DPoP proof for sender-constrained access tokens;
- `ath` validation where required;
- nonce support only if/when a complete interoperable server nonce policy is implemented.

Do not claim socket/TLS channel binding that DPoP does not provide.

---

## 13. OpenID Connect provider core

### 13.1 OIDC activation

OIDC semantics activate only when `openid` is in the approved/requested scope and the client/server profile allows OIDC.

OAuth requests without `openid` must not accidentally receive ID Tokens or OIDC-specific subject/claim behavior.

### 13.2 Authorization request additions

Validate and model:

- `nonce`;
- `prompt` values supported by the server profile;
- `max_age`;
- OIDC scopes (`openid`, `profile`, `email`, etc.) through application claim policy;
- requested `acr_values` when supported;
- safe interaction requirements (`login`, `consent`, `select_account`) as framework-neutral decisions.

Epicrypt tells the framework **what interaction is required**, not how to render or perform it.

### 13.3 ID Token issuer

Build on current `OpenIdIdTokenValidator` by adding the corresponding issuer/profile service.

Required behavior:

- issuer/client/audience binding;
- `sub` from a framework-provided subject mapper;
- `iat`/`exp`;
- `auth_time` when required;
- nonce;
- `acr`/`amr` when supplied/required;
- `azp` for multi-audience cases;
- `at_hash`, `c_hash` and other required half-hashes according to response/token context;
- KeyRing/asymmetric signing-key readiness;
- optional client-configured ID-token encryption only when algorithms/keys are explicitly allowed.

### 13.4 Subject identifiers

Epicrypt must not assume application account IDs are always the public OIDC `sub`.

Define a `OidcSubjectIdentifierProviderInterface` so frameworks can provide:

- public subject identifiers;
- pairwise identifiers if implemented later;
- tenant/provider-specific stable subject policy.

No database implementation belongs in Epicrypt.

### 13.5 UserInfo

Provide transport-neutral UserInfo claim resolution:

- verify OAuth/OIDC access token and `openid` context;
- subject binding must match the authorization;
- call application `OidcClaimsProviderInterface` for allowed claims;
- project only claims permitted by granted scopes/policy;
- return typed claim map, not an HTTP response.

### 13.6 Discovery

Expose OpenID Provider Configuration derived from the active OAuth/OIDC profile and framework-supplied endpoint URIs.

Do not implement route registration or dynamic URL discovery from globals.

---

## 14. Generic personal/API token core

### 14.1 Public model

Suggested public types:

```text
PersonalAccessTokenManager
PersonalAccessTokenIssue
PersonalAccessTokenResult
PersonalAccessTokenRecord
PersonalAccessTokenStoreInterface
PersonalAccessTokenPolicy
PersonalAccessTokenAbilities
```

Final naming should avoid framework-specific branding while documenting “Sanctum-style” behavior as the design reference.

### 14.2 JWT claims

Use a distinct signed JWT profile, for example `typ=pat+jwt`, containing bounded claims such as:

```text
iss?            # optional/configured for application tokens
sub
jti
iat
exp? 
name            # bounded label or label id
aabilities       # final name must be corrected to `abilities`; bounded unique list
token_use=personal_access
```

**Implementation note:** the typo-like placeholder above is not a wire decision; final claims must use the canonical `abilities` key after the claim-shape review.

Keep token values small. Ability/item count and total encoded token size are security bounds.

### 14.3 Store semantics

The store persists metadata, never the raw JWT:

- `jti`;
- subject id;
- name;
- abilities or canonical ability digest/metadata according to final design;
- created/expiry/revoked timestamps;
- optional last-used metadata;
- optional token-version/policy marker.

Verification is **stateful by default** for this Sanctum-style path so immediate revocation works.

### 14.4 Ability semantics

- exact string matching by default;
- bounded unique ability list;
- no implicit hierarchical wildcard matching;
- `*` means all only when explicitly permitted by policy;
- `can($ability)` / `cannot($ability)` helpers operate on a fully verified active token result;
- application permission/authorization remains outside Epicrypt.

### 14.5 Management API

Transport-neutral operations:

```text
issue(subject, name, abilities, expiry?)
verify(jwt, expectedIssuer/context?)
list(subject)
revoke(jti, subject?)
revokeAll(subject)
```

Optional operations such as rename/touch-last-used must be separate store capabilities so the hot validation path does not require a database write on every request.

---

## 15. Persistence contracts and atomicity

Epicrypt ships **no DBLayer, PDO, ORM, SQL, Redis or CacheLayer implementation** for the auth protocol stores.

Test-only in-memory/fault-injection stores are allowed under `tests/`.

Every public store interface must document:

- uniqueness keys;
- atomic operations;
- expected conflict result;
- idempotency;
- expiry semantics;
- revocation semantics;
- whether stale reads are security-sensitive;
- required consistency for multi-process/distributed deployment.

Critical atomic boundaries:

- authorization code consume;
- refresh-token rotate/consume/reuse detection;
- refresh family revoke;
- DPoP/client-assertion replay claim;
- personal-token revoke/revoke-all versus verification;
- access-token revocation/status lookup when configured as authoritative.

No API may imply that `find()` then `delete()` is sufficient for one-time credentials.

---

## 16. Server/application policy object

Protocol behavior must be configurable without a framework config dependency.

Introduce typed immutable policy/config value objects, not a giant associative array.

Areas include:

- issuer;
- allowed grants;
- TTL ceilings/defaults;
- allowed algorithms;
- access-token audiences;
- PKCE requirement;
- allowed client auth methods;
- DPoP enabled/required policy;
- OIDC enabled profile and ID-token algorithms;
- parameter/token/claim size limits;
- clock skew;
- refresh reuse response;
- personal-token bounds.

Deployment paths, route paths and database/cache configuration do not belong here.

---

## 17. Protocol parser and limit policy

Reuse the existing centralized `JosePolicy` approach and create equivalent bounded OAuth/OIDC parameter policies rather than scattered magic numbers.

Limits must cover at least:

- total parameter count;
- parameter-name bytes;
- individual value bytes;
- state/nonce/verifier/challenge/client-id/redirect bytes;
- scope and audience count/total bytes;
- JWT/JWE compact size;
- claim count/depth/member count;
- JWKS key/member count;
- personal-token ability count/bytes;
- metadata/discovery size;
- store-returned collection count where a public API lists records.

Reject malformed/oversized input before expensive signature, decryption, password-hash or repository work whenever possible.

---

## 18. Error/result model

### 18.1 OAuth

Stable typed errors for:

```text
invalid_request
invalid_client
invalid_grant
unauthorized_client
unsupported_grant_type
invalid_scope
unsupported_response_type
access_denied
server_error
```

Add extension errors only when defined by the adopted specification/profile.

### 18.2 OIDC

Map OIDC-specific request/interaction errors without leaking authentication/account details.

### 18.3 Personal tokens

Use application-safe verification reasons such as:

```text
VALID
MALFORMED
INVALID_SIGNATURE
WRONG_TOKEN_CLASS
EXPIRED
NOT_YET_VALID
UNKNOWN_TOKEN
REVOKED
SUBJECT_MISMATCH
ABILITY_MISSING
POLICY_MISMATCH
```

Expected invalid credentials should return typed results where practical; configuration/programmer failures remain exceptions.

---

## 19. Foundation migration target

Once the Epicrypt protocol core is accepted, Foundation becomes an adapter/consumer.

### Foundation removes/reduces

- generic OAuth request validator;
- grant dispatcher/token manager protocol logic;
- PKCE implementation;
- authorization-code protocol implementation;
- refresh protocol/reuse implementation;
- generic OAuth revocation/introspection behavior;
- generic authorization-server metadata builder;
- generic client protocol model where no Foundation policy remains;
- Epicrypt-specific OAuth adapters that exist only because the protocol core currently lives in Foundation.

### Foundation keeps

- DBLayer implementations of Epicrypt store interfaces;
- auth schema/migrations;
- account/principal lookup and mapping;
- scope → Foundation permission mapping;
- consent UI/application policy;
- OAuth routes/Webrick handlers;
- rate limiting;
- audit/events;
- CLI administration commands;
- config/env/key locators;
- middleware/principal adaptation.

### Migration evidence

Before deletion, freeze representative Foundation behavior for:

- public Authorization Code + S256;
- confidential Authorization Code;
- Client Credentials;
- Refresh rotation and replay;
- access JWT claims;
- revocation;
- introspection;
- metadata/JWKS;
- invalid redirect/PKCE/scope/client cases;
- consent approval/denial interaction.

The same vectors must pass through Epicrypt core + thin Foundation adapters.

---

## 20. Existing Foundation token/state migration

New auth credentials are JWT/JOSE-based, but already-issued Foundation credentials/state must have an explicit rollout policy.

During implementation audit determine whether current Foundation OAuth 2.1 has production/published persistence requiring compatibility.

If compatibility is required:

- stop issuing legacy token/code formats first;
- allow a bounded read-only legacy verifier/consumer only for the maximum remaining TTL;
- never reissue a legacy format;
- preserve refresh-family reuse/revocation evidence until every legacy refresh token is impossible to use;
- keep fallback OAuth signing public keys until all legacy access JWTs expire;
- remove compatibility code in a later explicitly scheduled cleanup.

Do not invent permanent dual-format complexity without evidence that persisted consumers need it.

---

## 21. Test strategy

### 21.1 Shared JOSE/token tests

- strict token-class substitution matrix;
- wrong issuer/audience/key purpose/algorithm;
- active/fallback signing-key rotation;
- malformed/oversized JWT/JWE/JWK/JWKS;
- duplicate claims/parameters;
- key confusion and algorithm confusion;
- clock boundary and skew tests;
- sensitive parameter/reflection audit.

### 21.2 OAuth 2.1 tests

- Authorization Code + S256 happy path;
- code replay and concurrent double consume;
- redirect mismatch;
- verifier mismatch;
- public/confidential client auth rules;
- client secret and private-key-JWT authentication;
- assertion replay;
- client credentials;
- scope/audience narrowing and escalation rejection;
- refresh rotation/reuse/concurrency/family revocation;
- access JWT validation;
- revocation/introspection behavior;
- RFC 9700 negative vectors;
- authorization-server issuer/mix-up defenses where profile applies.

### 21.3 OIDC tests

- `openid` activation boundary;
- nonce;
- ID-token audience/`azp`;
- `auth_time`/`max_age`;
- `acr`/`amr`;
- `at_hash`/`c_hash`;
- subject mapping;
- UserInfo scope projection;
- discovery metadata;
- OAuth access token cannot validate as ID Token and vice versa;
- optional encrypted ID Token interoperability if enabled.

### 21.4 Personal/API token tests

- issue/verify;
- exact abilities;
- wildcard policy;
- expiry;
- revoke one/revoke all;
- concurrent revoke/verify semantics according to store contract;
- listing metadata never returns raw JWT;
- wrong subject/token class/key purpose;
- optional last-used capability without mandatory hot-path writes;
- persistent-worker/Fiber state isolation.

### 21.5 Foundation extraction tests

Run existing Foundation OAuth suites first as frozen behavior evidence, then migrate them to adapter-contract/integration tests against Epicrypt.

---

## 22. Interoperability and external vectors

Do not validate an OAuth/OIDC implementation only against itself.

Required independent checks where feasible:

- JOSE/JWT access tokens against an independent JWT implementation;
- RFC 9068 claim/header vectors;
- `private_key_jwt` vectors;
- DPoP RFC examples/independent verifier;
- OIDC ID-token hashes and claim validation against published examples/another implementation;
- discovery/JWKS consumption through a minimal independent client fixture;
- Authorization Code/PKCE vectors from RFC examples;
- negative malformed/duplicate/oversized corpus.

If a third-party conformance suite can run reproducibly in CI without creating a fragile external service dependency, add it as a release gate; otherwise provide a documented local conformance command and freeze the resulting vectors.

---

## 23. Mutation/static/security gates

Add dedicated mutation shards rather than relying on broad incidental coverage:

```text
oauth-authorization
oauth-token-grants
oauth-refresh-revocation
oauth-client-auth
oidc-provider
personal-access-token
```

Existing JOSE/DPoP/Remote-JOSE shards remain green.

Security/static requirements:

- PHP 8.4/8.5 lowest/stable;
- PHPStan/Psalm/PHPForge clean;
- dependency audit clean;
- no secret-bearing diagnostics;
- cognitive complexity caps retained;
- no global mutable trust/client/request state;
- no route/framework/DB dependency added to production Composer requirements.

---

## 24. Performance plan

Correct protocol/security behavior is not weakened for benchmark numbers.

Measure attribution for:

1. JWT access-token issue/verify;
2. authorization-code JWE issue/consume;
3. refresh JWT/JWE parse + store rotation;
4. DPoP proof validation;
5. ID Token issue/verify;
6. personal token issue/verify with store lookup;
7. direct Epicrypt endpoint operation versus thin Foundation/Webrick adapter;
8. active-key versus fallback-key verification;
9. persistent worker repeated validation for memory growth;
10. capability-absent cost when OAuth/OIDC/PAT services are not composed.

Database/network/KDF/HTTP costs are measured separately from Epicrypt CPU/adapter overhead.

---

## 25. Documentation deliverables

Before release add/update:

- architecture overview for the three auth paths;
- OAuth 2.1 server-core guide;
- OIDC provider guide;
- personal/API token guide;
- framework-adapter guide showing route/HTTP adaptation;
- persistence-contract guide with atomicity requirements;
- Foundation migration guide;
- key-purpose/rotation guide across the auth token classes;
- security hardening/deployment checklist;
- standards matrix listing implemented RFC/draft/OIDC profiles and intentional exclusions;
- examples that do not require a framework or database implementation.

Never market the Sanctum-style core as Laravel Sanctum compatibility. It is a generic JWT personal-token system inspired by the same developer-facing management model.

---

## 26. Implementation phases and checkboxes

### Phase A — rebaseline and extraction freeze

- [ ] Capture exact Epicrypt current branch/API baseline and keep previous green release matrix as non-regression evidence.
- [ ] Inventory every Foundation `Auth/OAuth` class, contract, DBLayer adapter, route/handler, schema and test.
- [ ] Classify each as move / replace-with-Epicrypt-contract / keep-in-Foundation.
- [ ] Freeze Foundation OAuth 2.1 happy/negative vectors before moving code.
- [ ] Freeze current Epicrypt JWT/OIDC/DPoP/refresh-token public surface.
- [ ] Create an auth-protocol public API inventory and update it every batch.

### Phase B — shared auth-token/JWT profile substrate

- [ ] Add explicit auth token classes/media types and cross-token substitution policy.
- [ ] Implement JWT access-token RFC 9068 profile.
- [ ] Implement JOSE authorization-code artifact profile.
- [ ] Implement JOSE refresh-token artifact profile over authoritative family state.
- [ ] Add explicit key purposes for OAuth/OIDC/PAT credentials.
- [ ] Centralize auth-parameter/token/claim bounds.
- [ ] Add token-class substitution/security mutation tests.

### Phase C — client, store and endpoint contracts

- [ ] Implement framework-neutral OAuth client model/policy.
- [ ] Implement client-secret verification and `private_key_jwt` validation/replay contract.
- [ ] Define authoritative public store interfaces and atomicity semantics.
- [ ] Define protocol request/response/error DTOs.
- [ ] Define endpoint catalog/capability metadata with no route registration.
- [ ] Provide test-only in-memory/fault stores.

### Phase D — OAuth 2.1 authorization core

- [ ] Extract/harden Foundation authorization request validation.
- [ ] Exact redirect + code response + PKCE S256.
- [ ] Scope/audience bounded resolution hooks.
- [ ] Authentication/consent interaction result model.
- [ ] JOSE authorization-code issue + atomic consume.
- [ ] OAuth protocol errors and redirect safety.
- [ ] RFC 9700 negative vectors.

### Phase E — OAuth 2.1 token/core lifecycle

- [ ] Authorization Code exchange.
- [ ] Client Credentials.
- [ ] JWT/JWE Refresh Token rotation and reuse detection.
- [ ] JWT access-token issuance/validation.
- [ ] Revocation.
- [ ] Introspection.
- [ ] Authorization-server metadata.
- [ ] JWKS publication.
- [ ] Integrate DPoP into token issuance/resource validation.
- [ ] Dedicated OAuth mutation/interoperability gates.

### Phase F — OpenID Connect 1.0 provider

- [ ] OIDC request extensions and `openid` activation.
- [ ] interaction requirements for nonce/prompt/max_age/acr.
- [ ] ID Token issuer paired with existing validator.
- [ ] subject identifier provider contract.
- [ ] UserInfo claims provider/projection.
- [ ] OIDC discovery metadata.
- [ ] optional encrypted ID Token profile only if independent interoperability passes.
- [ ] OIDC negative/conformance vectors and mutation gate.

### Phase G — generic personal/API tokens

- [ ] Finalize public generic name/API (Sanctum-style semantics, no Laravel dependency).
- [ ] `pat+jwt` profile and separate key purpose.
- [ ] issue/verify/list/revoke/revoke-all public service.
- [ ] bounded exact abilities + explicit wildcard policy.
- [ ] authoritative store contract; raw JWT never persisted.
- [ ] optional last-used capability without forced write-on-read.
- [ ] state/concurrency/Fiber/persistent-runtime tests.
- [ ] dedicated mutation/performance coverage.

### Phase H — Foundation extraction and adapter proof

- [ ] Add Foundation DBLayer implementations of Epicrypt store contracts.
- [ ] Replace Foundation protocol classes with Epicrypt services.
- [ ] Keep Foundation routes/Webrick/consent/audit/rate-limit/principal mapping only.
- [ ] Remove obsolete `Adapter/Epicrypt/OAuth` indirection where Foundation can consume Epicrypt directly.
- [ ] Preserve/migrate existing OAuth persisted state/tokens only where evidence requires it.
- [ ] Run the existing Foundation OAuth flow suites against the extracted core.
- [ ] Update Foundation plan/docs to make Epicrypt the OAuth/OIDC/PAT protocol owner.

### Phase I — release hardening

- [ ] Complete standards delta review for latest OAuth 2.1 draft/RFC at release time.
- [ ] Complete OIDC Core/Discovery Errata 2 requirements matrix.
- [ ] Run all Epicrypt pre-extension A–H regression gates.
- [ ] Run new OAuth/OIDC/PAT mutation shards.
- [ ] Run PHP 8.4/8.5 lowest/stable QA and analyzers.
- [ ] Run independent JOSE/OAuth/OIDC interoperability vectors.
- [ ] Run performance attribution and persistent-runtime memory checks.
- [ ] Complete docs/migration/public API inventory.
- [ ] Prove Foundation composition/integration on PHP 8.4/8.5.
- [ ] Mark PR release-ready only after this exact final SHA is green.

---

## 27. Initial non-goals for Epicrypt 3 auth-core release

Unless a concrete consumer requirement changes the plan with tests and interoperability evidence, do not expand the first auth-core release to include:

- Resource Owner Password Credentials;
- OAuth implicit grant;
- OIDC implicit/hybrid flows;
- Dynamic Client Registration;
- OAuth Device Authorization Grant;
- Token Exchange;
- PAR/JAR/JARM;
- mTLS sender-constrained tokens/client authentication;
- OIDC federation;
- OIDC logout profiles;
- social-provider SDKs;
- login/session UI;
- consent UI;
- route registration;
- DB/ORM/cache implementations.

These are extension candidates after the three core paths are stable. DPoP is already in scope because Epicrypt has the primitive and it directly strengthens the OAuth access-token path.

---

## 28. Final target

Epicrypt 3 is complete when a framework can implement only transport/application/persistence adapters and obtain all three secure authentication paths from one reusable core:

```text
Framework / Foundation
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

No framework should need to reimplement protocol cryptography or state-machine semantics above this surface.

---

## 29. Immediate next batch

**Start with Phase A only.**

1. Rescan Foundation's current OAuth 2.1 source/tests/contracts end-to-end.
2. Produce the move/keep/replace inventory.
3. Freeze Foundation behavior fixtures.
4. Inventory current Epicrypt JWT/JOSE/OIDC/DPoP/refresh primitives against the target token-class architecture.
5. Update this plan ledger with the exact findings before beginning Phase B.
