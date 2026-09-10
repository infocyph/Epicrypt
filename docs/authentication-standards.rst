Authentication standards profile
================================

This page records the standards profile implemented by Epicrypt 3.0. It is a
release contract, not a claim that Epicrypt is an HTTP server or a complete
identity product. Epicrypt owns protocol/security mechanics and typed results;
the host application owns transport, login/consent UI, persistence adapters,
rate limiting, audit and application authorization policy.

Release baseline
----------------

The release review on 2026-09-10 uses these normative baselines:

- OAuth 2.1 ``draft-ietf-oauth-v2-1-15``. OAuth 2.1 is still an Internet-Draft;
  Epicrypt does not claim compliance with a finalized OAuth 2.1 RFC.
- RFC 9700, OAuth 2.0 Security Best Current Practice.
- RFC 7636, PKCE, with the Epicrypt profile restricted to ``S256``.
- RFC 9207, authorization-server issuer identification.
- RFC 8414, authorization-server metadata.
- RFC 7009, token revocation.
- RFC 7662, token introspection.
- RFC 9068, JWT access-token profile.
- RFC 7523, JWT client authentication/assertions.
- RFC 9449, DPoP.
- OpenID Connect Core 1.0 incorporating Errata Set 2.
- OpenID Connect Discovery 1.0 incorporating Errata Set 2.

A newer OAuth 2.1 draft or RFC published before the 3.0 tag requires a delta
review before release.

OAuth 2.1 profile
-----------------

.. list-table::
   :header-rows: 1
   :widths: 28 16 56

   * - Requirement / feature
     - 3.0 status
     - Epicrypt behavior
   * - Authorization Code grant
     - Supported
     - Exact registered redirect URI, ``response_type=code``, one-time
       authorization-code state and mandatory PKCE ``S256``.
   * - PKCE ``plain``
     - Rejected
     - ``S256`` is the only accepted code-challenge method.
   * - Implicit grant
     - Excluded
     - No implicit or token response from the authorization endpoint.
   * - Resource Owner Password Credentials
     - Excluded
     - No password grant API.
   * - Client Credentials
     - Supported
     - Confidential authenticated clients only; requested scopes and resource
       audiences are bounded by client registration.
   * - Refresh Token
     - Supported
     - Encrypted refresh artifacts plus authoritative rotation, reuse detection,
       family/authorization revocation and scope narrowing.
   * - Public-client token endpoint authentication
     - Supported profile
     - Public Authorization Code clients may be unauthenticated at the token
       endpoint; PKCE remains mandatory. Confidential clients must authenticate.
   * - ``client_secret_basic``
     - Supported
     - Bound to registered confidential clients.
   * - ``private_key_jwt``
     - Supported
     - Strict JOSE header/algorithm/key policy, exact client identity/audience,
       bounded temporal claims and replay consumption.
   * - JWT access tokens
     - Supported
     - RFC 9068 ``at+jwt`` profile with issuer, audience, subject, client,
       expiration and optional scope/authorization/DPoP confirmation state.
   * - Token revocation
     - Supported
     - RFC 7009-style non-oracular acceptance; authoritative refresh and
       access-token state is revoked when available.
   * - Token introspection
     - Supported
     - RFC 7662-style protected introspection; unauthenticated/invalid clients
       do not receive token state.
   * - Authorization-server metadata
     - Supported
     - Capabilities are emitted from the configured endpoint/grant/client-auth
       catalog instead of advertising unsupported features.
   * - DPoP
     - Supported
     - Proof signature, method/URI, replay and access-token confirmation binding
       are validated before sender-constrained use.
   * - Query-string bearer token
     - Excluded
     - Epicrypt exposes no query bearer-token acceptance path.

OpenID Connect Core profile
---------------------------

Epicrypt 3.0 supports the OpenID Connect Authorization Code profile. ``openid``
is the exact activation scope; without it, the request remains ordinary OAuth.

.. list-table::
   :header-rows: 1
   :widths: 30 16 54

   * - Core requirement / feature
     - 3.0 status
     - Epicrypt behavior
   * - Authorization Code flow
     - Supported
     - OIDC request processing extends the validated OAuth Authorization Code
       request; implicit and hybrid flows are not exposed.
   * - ``nonce``
     - Supported
     - Bounded request value is carried into the ID Token and can be validated
       by ``OpenIdIdTokenValidator``.
   * - ``prompt``
     - Supported
     - ``none``, ``login``, ``consent`` and ``select_account`` are typed.
       ``none`` cannot be combined with another prompt. Required interaction
       under ``none`` returns the corresponding OIDC interaction error.
   * - ``max_age`` / ``auth_time``
     - Supported
     - ``max_age`` can force reauthentication; ID Tokens carry ``auth_time``
       when authentication state is available.
   * - ``acr`` / ``acr_values``
     - Supported
     - Requested ACR values are bounded; interaction requires an acceptable
       authentication context and the resulting ID Token can carry ``acr``.
   * - ``amr``
     - Supported
     - Bounded authentication-method values are carried into the ID Token.
   * - ID Token ``iss`` / ``sub`` / ``aud``
     - Supported
     - Issuer and audience are fixed by trusted provider/client state; subject
       identifiers are supplied by the host's subject-identifier provider.
   * - ``azp``
     - Validated where applicable
     - ID-token validation enforces the authorized-party rule for multi-audience
       tokens; Epicrypt's provider-issued ID Token targets the requesting client.
   * - ``at_hash``
     - Supported
     - Emitted when an access token is bound into ID-token issuance and checked
       when supplied to the validator.
   * - ``c_hash``
     - Supported
     - Authorization Code token responses forward the actual code to ID-token
       issuance; the resulting ``c_hash`` is validation-covered.
   * - ``s_hash``
     - Supported by issuer/validator
     - Available when state is intentionally bound during ID-token issuance.
   * - UserInfo
     - Supported core projection
     - A host claims provider supplies bounded claims; ``sub`` remains owned by
       the subject-identifier provider and cannot be overridden by claim data.
   * - Public and pairwise subject types
     - Supported abstraction
     - ``OpenIdSubjectType`` exposes both; the host provider owns the actual
       stable/pairwise identifier derivation policy.
   * - ID-token encryption
     - Excluded from required 3.0 provider scope
     - General JWE remains available, but the OIDC provider API does not claim
       encrypted-ID-token interoperability in 3.0.
   * - Implicit / Hybrid OIDC flows
     - Excluded
     - No provider API advertises or issues those response types.
   * - Dynamic client registration
     - Excluded
     - Client administration is host/application policy.
   * - Session management / front-channel / back-channel logout
     - Excluded
     - Session ownership and logout transport are outside the 3.0 provider core.
   * - Request Objects, PAR, JAR and JARM
     - Excluded
     - These profiles are not advertised by Epicrypt 3.0.

OpenID Connect Discovery profile
--------------------------------

``OpenIdProviderMetadata`` extends capability-accurate OAuth authorization-server
metadata and requires an absolute HTTPS UserInfo endpoint plus issuer-matched
OIDC signing keys.

.. list-table::
   :header-rows: 1
   :widths: 34 16 50

   * - Discovery metadata
     - 3.0 status
     - Behavior
   * - ``issuer``
     - Required
     - Comes from the OAuth metadata/signing-key issuer and must stay exact.
   * - ``authorization_endpoint``
     - Required for OIDC provider metadata
     - Provider construction fails if unavailable.
   * - ``token_endpoint``
     - Required for OIDC provider metadata
     - Provider construction fails if unavailable.
   * - ``jwks_uri``
     - Required
     - Provider construction fails if unavailable; published keys remain
       purpose-scoped public verification material.
   * - ``userinfo_endpoint``
     - Required by Epicrypt profile
     - Must be an absolute HTTPS URI without credentials or fragment.
   * - ``subject_types_supported``
     - Required
     - Non-empty typed unique list.
   * - ``id_token_signing_alg_values_supported``
     - Required
     - Advertises the configured OIDC ID-token signing algorithm only.
   * - ``scopes_supported``
     - Supported
     - Bounded unique scope list and must include ``openid``.
   * - ``claims_supported``
     - Supported
     - Bounded unique claim names and must include ``sub``.

Host responsibilities and non-claims
------------------------------------

Epicrypt does not register HTTP routes, serialize framework responses, perform
end-user login, render consent UI, choose accounts, implement database/cache
stores, or decide application permissions. Adapters must preserve Epicrypt's
validated redirect, client, authorization, replay and revocation decisions
without reinterpreting them.

The following are therefore not exclusions from protocol validation; they are
intentional ownership boundaries: TLS termination, endpoint routing, HTTP
status/header mapping, cookie/session policy, principal lookup, consent history,
rate limiting, audit/telemetry and durable transaction/locking implementations.

Release evidence
----------------

Epicrypt 3.0 is release-ready only when the exact release commit passes the
ordinary PHP 8.4/8.5 QA/analyzer matrix, dependency/security audit, independent
JOSE interoperability, positive AEGIS runtime gate, all security-critical
mutation shards (including OAuth/OIDC/PAT), parser/negative vectors,
performance/persistent-runtime evidence and the final public-API freeze. No
skipped test, reduced mutation threshold or release-only suppression is accepted.
