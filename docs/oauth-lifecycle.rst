Complete OAuth token lifecycle
==============================

This example covers Epicrypt's complete part of an OAuth deployment: RFC 9068
access-token issuance and verification, opaque refresh-token rotation, scope
narrowing, optional DPoP sender binding and revocation.

Epicrypt is not an OAuth authorization server. The host application remains
responsible for authorization-code and PKCE validation, exact redirect-URI
matching, client authentication, consent, HTTPS endpoints, rate limiting and
OAuth JSON responses. The example begins only after those protocol checks have
produced an authenticated subject, client and approved scope set.

One-time service setup
----------------------

Generate the signing key offline and load it from protected deployment
configuration in production. Give resource servers only the public key.
``$refreshTokenStore`` is the durable transactional implementation described in
:doc:`token-storage`; ``$dpopReplayStore`` is a shared
``JwtReplayStoreInterface`` implementation.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
   use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenManager;

   // Provision once; production processes load these values from secret storage.
   $signingKeys = KeyPairGenerator::ec(OpenSslCurveName::PRIME256V1)->generate();
   $accessTokenIssuer = AsymmetricJwt::issuer(
       $signingKeys['private'],
       type: 'at+jwt',
       keyId: 'oauth-signing-2026-08',
   );
   $accessTokenVerifier = AsymmetricJwt::verifier(
       $signingKeys['public'],
       JwtPolicy::oauthAccessToken('https://auth.example.com', 'orders-api'),
   );
   $refreshTokens = new RefreshTokenManager($refreshTokenStore);

   $issueAccessToken = static function (
       RefreshTokenGrant $grant,
   ) use ($accessTokenIssuer): string {
       $customClaims = [
           'client_id' => $grant->clientId,
       ];
       if ($grant->scopes !== []) {
           $customClaims['scope'] = $grant->scopes;
       }
       if ($grant->dpopKeyThumbprint !== null) {
           $customClaims['cnf'] = ['jkt' => $grant->dpopKeyThumbprint];
       }

       return $accessTokenIssuer->issue(JwtClaims::issue(
           issuer: 'https://auth.example.com',
           subject: $grant->subject,
           audiences: $grant->audiences,
           ttlSeconds: 300,
           custom: $customClaims,
       ));
   };

Initial token endpoint response
-------------------------------

After the application has consumed a valid authorization code, create one
authorization grant. If the client used DPoP at the token endpoint, set
``$verifiedDpopThumbprint`` from ``DpopProof::verifyResult()``; otherwise use
``null``.

.. code-block:: php

   <?php

   declare(strict_types=1);

   $grant = new RefreshTokenGrant(
       id: sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
       subject: $authenticatedUserId,
       clientId: $authenticatedClientId,
       audiences: ['orders-api'],
       scopes: $approvedScopes,
       expiresAt: time() + 90 * 24 * 60 * 60,
       dpopKeyThumbprint: $verifiedDpopThumbprint,
   );

   $accessToken = $issueAccessToken($grant);
   $refreshToken = $refreshTokens->issue($grant);

   $tokenResponse = [
       'access_token' => $accessToken,
       'token_type' => $grant->dpopKeyThumbprint === null ? 'Bearer' : 'DPoP',
       'expires_in' => 300,
       'refresh_token' => $refreshToken,
   ];
   if ($grant->scopes !== []) {
       $tokenResponse['scope'] = implode(' ', $grant->scopes);
   }

Return this structure as an OAuth JSON response over TLS with
``Cache-Control: no-store`` and ``Pragma: no-cache``. Never log either token.

Resource-server request
-----------------------

The API fixes issuer, audience, type and algorithm in trusted configuration.
After verification, enforce the endpoint's required scope. For a DPoP token,
verify the proof and bind it to the access token before authorization.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\DpopProof;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;

   $verifiedAccessToken = $accessTokenVerifier->verifyResult($presentedAccessToken);
   if (!$verifiedAccessToken->valid) {
       throw new RuntimeException('Return an OAuth invalid_token response.');
   }

   $confirmation = $verifiedAccessToken->claims['cnf'] ?? null;
   if ($confirmation !== null) {
       $verifiedProof = new DpopProof()->verifyResult(
           $presentedDpopProof,
           $requestMethod,
           $absoluteRequestUri,
           AsymmetricJwtAlgorithm::EDDSA,
           $dpopReplayStore,
           accessToken: $presentedAccessToken,
           nonce: $expectedDpopNonce,
       );
       new DpopProof()->validateAccessTokenBinding(
           $verifiedAccessToken->claims,
           $verifiedProof['publicJwk'],
       );
   }

   $grantedScopes = explode(' ', (string) ($verifiedAccessToken->claims['scope'] ?? ''));
   if (!in_array('orders:read', $grantedScopes, true)) {
       throw new RuntimeException('Return an OAuth insufficient_scope response.');
   }

   $orders = $orderRepository->forUser($verifiedAccessToken->claims['sub']);

Refresh-token endpoint
----------------------

Authenticate confidential clients before this step. Public clients must use
rotation or another approved sender constraint. Verify a DPoP proof first when
the grant is sender-constrained, then pass only its verified thumbprint.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRotationStatus;

   $rotation = $refreshTokens->rotate(
       $presentedRefreshToken,
       $authenticatedClientId,
       $verifiedDpopThumbprint,
       requestedScopes: $requestedScopes,
   );

   if (!$rotation->rotated || $rotation->grant === null || $rotation->token === null) {
       if ($rotation->status === RefreshTokenRotationStatus::REUSED) {
           $securityEvents->refreshTokenFamilyReuseDetected($authenticatedClientId);
       }

       // Expose the same protocol error for invalid, expired, reused, revoked,
       // binding-mismatched, scope-mismatched and exhausted-conflict outcomes.
       throw new RuntimeException('Return OAuth invalid_grant.');
   }

   $replacementAccessToken = $issueAccessToken($rotation->grant);
   $refreshResponse = [
       'access_token' => $replacementAccessToken,
       'token_type' => $rotation->grant->dpopKeyThumbprint === null ? 'Bearer' : 'DPoP',
       'expires_in' => 300,
       'refresh_token' => $rotation->token,
   ];
   if ($rotation->grant->scopes !== []) {
       $refreshResponse['scope'] = implode(' ', $rotation->grant->scopes);
   }

The old refresh token is now retained as consumed history. Presenting it again
returns ``REUSED`` and the store revokes the entire family, including the
replacement. Requested scopes may stay equal or become narrower; they can
never expand.

Logout and security-event revocation
------------------------------------

Logout revokes the family identified by the presented refresh token. Account
disablement, authorization withdrawal and password compromise revoke every
family belonging to the authorization grant.

.. code-block:: php

   <?php

   declare(strict_types=1);

   $refreshTokens->revoke($presentedRefreshToken); // logout
   $refreshTokens->revokeGrant($authorizationGrantId); // wider security event

Access tokens already issued remain valid until their short expiration unless
the deployment selects a ``DENYLIST`` JWT policy and updates its shared replay
store. Refresh-token revocation must therefore complement, not replace,
short-lived access tokens.

DPoP-bound token endpoint requests
----------------------------------

Use the same verification path for initial issuance and refresh. The URI is the
absolute token-endpoint URI without credentials or fragment.

.. code-block:: php

   <?php

   declare(strict_types=1);

   $tokenEndpointProof = new DpopProof()->verifyResult(
       $presentedDpopProof,
       'POST',
       'https://auth.example.com/oauth/token',
       AsymmetricJwtAlgorithm::EDDSA,
       $dpopReplayStore,
       nonce: $expectedDpopNonce,
   );
   $verifiedDpopThumbprint = $tokenEndpointProof['keyThumbprint'];

Never calculate the binding from an unverified ``jwk`` header. Each accepted
proof is consumed atomically by issuer/thumbprint, JWT ID and expiration.
