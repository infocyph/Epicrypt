from pathlib import Path

PLAN = Path("docs/plans/epicrypt-3-final-development-plan.md")
INVENTORY = Path("docs/plans/epicrypt-3-public-api-inventory.md")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f"missing plan synchronization anchor: {label}")
    return text.replace(old, new, 1)


plan = PLAN.read_text()

plan = replace_once(
    plan,
    "- OAuth 2.1 `draft-ietf-oauth-v2-1-15` at plan creation; recheck latest draft/RFC before release;",
    "- OAuth 2.1 `draft-ietf-oauth-v2-1-16` (published 2026-09-03); release review completed against the current draft;",
    "OAuth 2.1 baseline",
)

plan = replace_once(
    plan,
    "- [ ] Add token/revocation/introspection/OIDC/PAT endpoint-specific DTOs in their implementation phases.\n- [ ] Add reusable fault/concurrency stores as later mutation/concurrency phases require them.",
    "- [x] Add token/revocation/introspection/OIDC/PAT endpoint-specific DTOs in their implementation phases. (`5b1ed2a5`, `2a28096f`)\n- [ ] Add reusable fault/concurrency fixtures required by the final mutation/concurrency hardening pass. (Phase H)",
    "Phase C endpoint DTOs",
)

old_e = """### Phase E — OAuth token/core lifecycle — NEXT

- [ ] Authorization Code token exchange.
- [ ] Client Credentials.
- [x] Refresh-token rotation/reuse state machine. (`168c7b3e`)
- [ ] Integrate refresh grant into OAuth token endpoint/result model.
- [ ] Access-token issuance/validation service over RFC 9068 profile.
- [ ] Optional authoritative access-token-status integration.
- [ ] Revocation (RFC 7009).
- [ ] Introspection (RFC 7662).
- [ ] Authorization-server metadata (RFC 8414 + current OAuth 2.1 capability set).
- [ ] Auth-scoped JWKS publication.
- [ ] DPoP issuance/resource integration.
- [ ] Token/revocation/introspection negative/interoperability vectors.
- [ ] Phase E plan/API inventory synchronization.
"""
new_e = """### Phase E — OAuth token/core lifecycle — COMPLETE

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
"""
plan = replace_once(plan, old_e, new_e, "Phase E")

old_f = """### Phase F — OpenID Connect provider

- [ ] OIDC request extensions/`openid` activation.
- [ ] nonce/prompt/max_age/acr interaction requirements.
- [ ] ID Token issuer paired with current validator.
- [ ] subject identifier provider contract.
- [ ] UserInfo claims provider/projection.
- [ ] discovery metadata.
- [ ] optional encrypted ID Token only after interoperability.
- [ ] OIDC conformance/negative vectors.
- [ ] Phase F plan/API inventory synchronization.
"""
new_f = """### Phase F — OpenID Connect provider — COMPLETE (3.0 required scope)

- [x] OIDC request extensions/`openid` activation. (`f187a02b`, `5b1ed2a5`)
- [x] nonce/prompt/max_age/acr interaction requirements. (`f187a02b`, `5b1ed2a5`)
- [x] ID Token issuer paired with hardened validator. (`5b1ed2a5`)
- [x] subject identifier provider contract. (`5b1ed2a5`)
- [x] UserInfo claims provider/projection. (`5b1ed2a5`)
- [x] discovery metadata. (`5b1ed2a5`)
- [x] Defer optional encrypted ID Token until independent encryption interoperability is intentionally added; it is not required for Epicrypt 3.0. (scope decision)
- [x] OIDC provider/negative vectors for the supported Authorization Code profile. (`5b1ed2a5`)
- [x] Phase F plan/API inventory synchronization. (this completeness pass)
"""
plan = replace_once(plan, old_f, new_f, "Phase F")

old_g = """### Phase G — generic personal/API tokens

- [ ] Final public manager/policy/abilities API.
- [ ] `pat+jwt` profile + key-purpose enforcement.
- [ ] issue/verify/list/revoke/revoke-all manager semantics.
- [ ] exact abilities + explicit wildcard policy.
- [x] authoritative metadata store; raw JWT never persisted. (`143b1c21`)
- [ ] optional last-used capability.
- [ ] concurrency/Fiber/persistent-runtime coverage.
- [ ] negative/performance vectors.
- [ ] Phase G plan/API inventory synchronization.
"""
new_g = """### Phase G — generic personal/API tokens — COMPLETE (implementation)

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
"""
plan = replace_once(plan, old_g, new_g, "Phase G")

plan = replace_once(
    plan,
    "### Phase H — Epicrypt release hardening\n\n- [ ] Latest OAuth 2.1 draft/RFC delta review.",
    "### Phase H — Epicrypt release hardening — IN PROGRESS\n\n- [x] Latest OAuth 2.1 draft/RFC delta review; baseline updated to `draft-ietf-oauth-v2-1-16`, including mandatory `iss` on redirectable authorization errors. (2026-09-09 completeness pass) ",
    "Phase H standards review",
)

old_next = """## 10. Immediate next batch

**Phase E only — OAuth token/core lifecycle.**

1. Build the transport-neutral token endpoint request/result/error model and client-authentication selection rules.
2. Implement Authorization Code exchange over `OAuthAuthorizationCodeConsumer`.
3. Implement RFC 9068 access-token issuer/validator service and optional authoritative status persistence.
4. Implement Client Credentials.
5. Integrate the completed JOSE refresh lifecycle into the token endpoint result model.
6. Then implement revocation, introspection, metadata, auth-scoped JWKS, and DPoP integration.
7. Add Phase E negative/interoperability vectors.
8. Update this plan and the public API inventory after Phase E is complete.
9. Keep full mutation/CI/release gates unchecked until Phase H executes them.
"""
new_next = """## 10. Immediate next batch

**Phase H only — Epicrypt 3.0 release hardening.**

1. Finish canonical PHPForge/Pint/PHPCS/Rector/PHPStan/Psalm cleanup on the completed A–G implementation.
2. Add the reusable fault/concurrency fixtures needed by the final authorization/refresh/PAT mutation and concurrency shards.
3. Replace stale mutation targets with the current OAuth/OIDC/PAT implementation shards and make the measured mutation floors green.
4. Complete the OIDC Core/Discovery Errata 2 requirements matrix and standards/exclusions documentation.
5. Run PHP 8.4/8.5 × prefer-lowest/prefer-stable QA/analyzers and dependency/security audit.
6. Run independent interoperability vectors plus auth/PAT performance and persistent-runtime memory attribution.
7. Finish docs, migration notes, and the public API inventory; remove temporary release-autofix tooling and obsolete unreleased surfaces.
8. Freeze the final public API inventory and record the exact release-ready SHA only after all Epicrypt gates are green.
9. Release Epicrypt 3.0; only then resume Foundation adoption.
"""
plan = replace_once(plan, old_next, new_next, "Immediate next batch")

PLAN.write_text(plan)

inventory = INVENTORY.read_text()

insert_anchor = "## Authorization protocol position\n"
addition = """## Phase E–G public authentication surfaces

| Surface | 3.0 decision | Evidence / notes |
| --- | --- | --- |
| `Auth\\OAuth\\OAuthTokenEndpoint/OAuthTokenResponse/OAuthTokenResult` | Add/final | `5b1ed2a5`; Authorization Code, Client Credentials, refresh and extension-capable token responses. |
| `Auth\\OAuth\\OAuthAccessTokenService/OAuthAccessTokenInspector/OAuthResourceAccessTokenValidator` | Add/final | `5b1ed2a5`; RFC 9068 issue/verify/resource validation with optional authoritative state. |
| `Auth\\OAuth\\OAuthRevocationEndpoint/OAuthRevocationResult` | Add/final | `5b1ed2a5`; RFC 7009 non-oracular revocation. |
| `Auth\\OAuth\\OAuthIntrospectionEndpoint/OAuthIntrospectionResponse/OAuthIntrospectionResult` | Add/final | `5b1ed2a5`; RFC 7662 protected introspection. |
| `Auth\\OAuth\\OAuthAuthorizationServerMetadata/OAuthJwksPublisher` | Add/final | `5b1ed2a5`; capability-accurate RFC 8414 metadata and purpose-scoped JWKS. |
| `Auth\\OAuth\\OAuthDpopContext/OAuthDpopValidator` | Add/final | `5b1ed2a5`; RFC 9449 proof/access-token binding integration. |
| `Auth\\Oidc\\OpenIdAuthorizationRequest*` + interaction model | Add/final | `f187a02b`, `5b1ed2a5`; exact `openid`, nonce/prompt/max_age/acr semantics. |
| `Auth\\Oidc\\OpenIdIdTokenIssuer/OpenIdIdTokenIssue/OpenIdTokenResponseExtension` | Add/final | `5b1ed2a5`; signed ID Tokens integrated into code exchange. |
| `Auth\\Oidc\\OpenIdSubjectIdentifierProviderInterface/OpenIdSubjectType` | Add/final | `5b1ed2a5`; public/pairwise subject abstraction. |
| `Auth\\Oidc\\OpenIdClaimsProviderInterface/OpenIdUserInfoProjector/OpenIdProviderMetadata` | Add/final | `5b1ed2a5`; UserInfo and discovery provider core. |
| encrypted ID Token public API | Do not add in required 3.0 scope | Deferred until explicitly justified by independent encryption interoperability. |
| `Auth\\Personal\\PersonalAccessTokenManager/Policy/Abilities/WildcardPolicy` | Add/final | `2a28096f`; stateful Sanctum-style PAT semantics. |
| `Auth\\Personal\\PersonalAccessTokenIssue/ValidationResult/ValidationStatus/UsageStoreInterface` | Add/final | `2a28096f`; issue-only raw JWT, authoritative metadata verification, optional usage tracking. |

"""
if addition not in inventory:
    if insert_anchor not in inventory:
        raise SystemExit("missing public API inventory insertion anchor")
    inventory = inventory.replace(insert_anchor, addition + insert_anchor, 1)

inventory = replace_once(
    inventory,
    "Current synchronization point: Phase D complete through `5f1fa6fc`.",
    "Current synchronization point: Phases E/F/G feature surfaces synchronized through `5b1ed2a5` and `2a28096f`; final release freeze remains a Phase H gate.",
    "API synchronization point",
)

INVENTORY.write_text(inventory)
