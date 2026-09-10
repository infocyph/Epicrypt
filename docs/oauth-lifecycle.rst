OAuth and OpenID Connect lifecycle
===================================

Epicrypt 3.0 provides the transport-neutral OAuth 2.1/OIDC protocol core. It
validates authorization requests, models authentication/consent interaction,
issues and atomically consumes authorization codes, authenticates clients,
issues RFC 9068 access tokens, rotates refresh tokens, performs revocation and
introspection, validates DPoP, publishes metadata/JWKS, and can extend an
Authorization Code exchange with an OIDC ID Token.

The host application still owns HTTP routing/serialization, TLS deployment,
login and consent UI, account/principal lookup, durable store implementations,
rate limiting, audit and application authorization policy. See
:doc:`authentication-standards` for the exact supported standards profile.

Service composition
-------------------

A deployment constructs Epicrypt services once from trusted configuration. The
store arguments below are host implementations of Epicrypt's public contracts;
Epicrypt intentionally ships no production database/cache adapter.

The principal objects are:

- ``OAuthAuthorizationRequestValidator`` for request/client/redirect/scope/PKCE
  validation;
- ``OAuthAuthorizationCodeIssuer`` and ``OAuthAuthorizationCodeConsumer`` for
  approved authorization and one-time code lifecycle;
- ``OAuthClientAuthenticator`` for confidential client authentication;
- ``OAuthAccessTokenService`` for RFC 9068 access-token issue/validation;
- ``RefreshTokenManager`` for encrypted refresh artifacts plus authoritative
  rotation/reuse state;
- ``OAuthTokenEndpoint`` for Authorization Code, Client Credentials and Refresh
  Token grant mechanics;
- ``OAuthRevocationEndpoint`` and ``OAuthIntrospectionEndpoint``;
- optional ``OAuthDpopValidator`` for sender-constrained tokens;
- optional ``OpenIdTokenResponseExtension`` for OIDC Authorization Code
  responses.

The signing/protection keys should use separate Epicrypt ``KeyPurpose`` domains
for OAuth access tokens, authorization codes, refresh tokens and OIDC ID Tokens.
Do not reuse one key purpose across credential classes.

Authorization request
---------------------

Pass the already parsed HTTP parameters to the authorization validator. The
validator accepts a bounded ``array<string, string|list<string>>`` envelope and
rejects duplicate singleton parameters rather than silently choosing one.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;

   $validator = new OAuthAuthorizationRequestValidator(
       clients: $clientStore,
       audienceResolver: $audienceResolver,
   );

   $result = $validator->validate([
       'client_id' => 'client-1',
       'redirect_uri' => 'https://client.example/callback',
       'response_type' => 'code',
       'scope' => 'orders:read openid',
       'state' => $state,
       'code_challenge' => $pkceChallenge,
       'code_challenge_method' => 'S256',
       'nonce' => $nonce,
   ]);

   if ($result->error !== null) {
       // Serialize only the redirect/error information returned by Epicrypt.
       // Never redirect to a request-controlled URI that Epicrypt rejected.
       return;
   }

   $request = $result->acceptedRequest();

OAuth 2.1 requires the exact registered redirect and Epicrypt's profile requires
PKCE ``S256``. ``plain``, implicit flow and wildcard/partial redirect matching
are not accepted.

Authentication and authorization interaction
--------------------------------------------

The application authenticates the end-user and renders consent/account UI, but
Epicrypt decides whether the protocol request is ready for those actions. For
OIDC requests, ``OpenIdInteractionPolicy`` evaluates ``prompt``, ``max_age``
and requested ACR values against host-supplied authenticated-session state.

After the host obtains an approved subject/scope decision, pass the validated
request and approval to ``OAuthAuthorizationCodeIssuer``. Epicrypt creates the
approved authorization state, stores only authoritative code metadata, and
returns the compact encrypted authorization-code artifact. The raw code is not
persisted.

The successful HTTP authorization response is constructed from Epicrypt's
result and includes RFC 9207 ``iss`` plus optional ``state``. User denial is an
``access_denied`` result from an already validated interaction; unsafe redirect
targets are never recovered from raw request input.

Token endpoint: Authorization Code
----------------------------------

Authenticate the client according to its registered method, then pass the
verified authentication result and raw token-endpoint inputs to
``OAuthTokenEndpoint``.

.. code-block:: php

   <?php

   declare(strict_types=1);

   $result = $tokenEndpoint->authorizationCode(
       clientId: $clientId,
       authentication: $clientAuthentication,
       code: $presentedCode,
       redirectUri: $presentedRedirectUri,
       pkceVerifier: $presentedPkceVerifier,
       dpopProof: $presentedDpopProof,
   );

   if (!$result->successful()) {
       // Map $result->error to the OAuth JSON/status response at the HTTP layer.
       return;
   }

   $response = $result->response;

The code is decrypted, rebound to the exact client/redirect/PKCE state and
atomically consumed before tokens are issued. Wrong client, redirect or PKCE
attempts do not consume a valid code. Once consumed, replay fails.

If refresh is permitted, the token endpoint issues a rotated-state refresh
artifact whose absolute lifetime is bounded by the approved authorization. The
access token is an RFC 9068 ``at+jwt``. When an OIDC
``OpenIdTokenResponseExtension`` is configured and the grant contains
``openid``, the response also includes an ``id_token``; its ``c_hash`` is bound
to the actual authorization code used in this exchange.

Client Credentials
------------------

Client Credentials is restricted to an authenticated confidential client.
Requested scopes must remain inside registration and the audience resolver must
return registered resource audiences. ``openid`` is rejected for this grant.

.. code-block:: php

   $result = $tokenEndpoint->clientCredentials(
       authentication: $clientAuthentication,
       requestedScopes: ['orders:read'],
       dpopProof: $presentedDpopProof,
   );

No refresh token is returned for Client Credentials.

Refresh rotation and reuse
--------------------------

Refresh tokens are compact JWE artifacts plus authoritative store state. The
raw artifact is never persisted. A successful refresh consumes the current
record and atomically installs a replacement in the same family.

.. code-block:: php

   $result = $tokenEndpoint->refreshToken(
       clientId: $clientId,
       authentication: $clientAuthentication,
       refreshToken: $presentedRefreshToken,
       requestedScopes: ['orders:read'],
       dpopProof: $presentedDpopProof,
   );

Requested scopes may remain equal or become narrower; they cannot expand beyond
the original grant or client registration. A sender-constrained refresh token
must be presented with the same verified DPoP key thumbprint.

If an already-consumed refresh token is presented again, Epicrypt drives the
reuse path and invalidates the family according to the authoritative store
contract. Adapters must implement the documented atomic rotation and family
revocation semantics across processes; a process-local cache is not sufficient.

Resource-server validation
--------------------------

Use ``OAuthResourceAccessTokenValidator`` at the resource boundary rather than
parsing JWT claims and enforcing them independently. Fix issuer/audience and
required endpoint scope in trusted application configuration. For DPoP access
tokens, pass the proof, HTTP method and absolute request URI so the validator can
verify proof/replay/``cnf.jkt`` binding before returning an active result.

The application authorizes business actions only after Epicrypt returns a valid
resource-token result. Do not trust unverified ``scope``, ``sub``, ``client_id``
or ``cnf`` claims from a decoded JWT.

Revocation and introspection
----------------------------

``OAuthRevocationEndpoint`` implements the non-oracular RFC 7009 behavior: an
authenticated client can submit a token and the external response remains
accepted even when the token is unknown. Known refresh/access/authorization
state is revoked according to client binding and configured authoritative
stores.

``OAuthIntrospectionEndpoint`` implements protected RFC 7662-style state
inspection. Invalid client authentication does not receive token state; unknown,
invalid, expired, reused or revoked credentials are reported inactive.

.. code-block:: php

   $revocation = $revocationEndpoint->revoke(
       clientId: $clientId,
       authentication: $clientAuthentication,
       token: $presentedToken,
       tokenTypeHint: $hint,
   );

   $inspection = $introspectionEndpoint->introspect(
       authentication: $clientAuthentication,
       token: $presentedToken,
       tokenTypeHint: $hint,
   );

DPoP
----

When DPoP is enabled, construct ``OAuthDpopValidator`` with a shared durable
``JwtReplayStoreInterface`` implementation and the allowed proof algorithms.
``OAuthTokenEndpoint`` validates token-endpoint proofs only against its trusted
absolute HTTPS token-endpoint URI. Resource validation binds the proof to the
actual method/URI and access token.

Never derive a sender binding from an unverified JWK header. Replay state must
be shared across all workers/instances that can accept the same proof.

OIDC provider extension
-----------------------

OIDC is activated only by the exact ``openid`` scope. Use
``OpenIdAuthorizationRequestValidator`` to extend the validated OAuth request,
``OpenIdInteractionPolicy`` for ``prompt``/``max_age``/ACR interaction, and an
``OpenIdIdTokenIssuer`` configured with issuer-matched
``OIDC_ID_TOKEN_SIGNING`` keys.

Configure ``OpenIdTokenResponseExtension`` on ``OAuthTokenEndpoint`` to add the
ID Token to successful Authorization Code responses. ``OpenIdUserInfoProjector``
combines the host's subject-identifier provider and claims provider while
preventing claims data from overriding ``sub``. ``OpenIdProviderMetadata``
projects Discovery metadata from the same configured OAuth capabilities and
OIDC signing policy.

Persistence and failure ordering
--------------------------------

Production adapters must preserve the atomicity documented by Epicrypt's store
interfaces. In particular:

- authorization-code consume is one-time and exact-state;
- refresh rotation/consume/reuse detection is atomic;
- refresh family and authorization revocation must become visible immediately;
- client-assertion and DPoP replay consumption must be shared across workers;
- authoritative access-token/PAT state must not be served from a stale ordinary
  cache after revocation;
- when token issuance fails after a one-time authorization transition, Epicrypt
  uses fail-closed revocation rather than attempting to resurrect consumed state.

HTTP adapters should emit OAuth/OIDC protocol errors from Epicrypt's typed
results, add the required transport headers (including ``Cache-Control:
no-store`` where appropriate), and never log raw authorization codes, access
credentials, refresh tokens, client assertions, DPoP proofs or ID Tokens.
