Tokens and JWT
==============

JWT keeps strict HS, RS, PS, ES, and EdDSA multi-algorithm support. Issuers and verifiers
are separate configurations, and the verifier fixes both ``alg`` and ``typ``;
an untrusted header can never select the verification algorithm.

Supported algorithms
--------------------

- Symmetric JWT: HS256, HS384, and HS512; the default is HS512.
- Asymmetric JWT: RS256/384/512, PS256/384/512, ES256/384/512, and Ed25519
  EdDSA; the default is ES256.
- HMAC minimum raw key sizes are 32, 48, and 64 bytes respectively.
- RSA keys must contain at least 2048 bits, and EC curves must match the
  configured ES algorithm.

Issue an access token across a service boundary
-----------------------------------------------

The authentication service keeps the EC private key. APIs receive only the
public key, so they can verify tokens without gaining issuance authority.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
   use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;

   $signingKeys = KeyPairGenerator::openSsl(type: OpenSslKeyType::EC)->generate();
   $claims = JwtClaims::issue(
       issuer: 'https://auth.example.com',
       subject: 'user-42',
       audiences: ['orders-api'],
       ttlSeconds: 300,
       custom: [
           'client_id' => 'browser-client',
           'scope' => 'orders:read orders:write',
       ],
   );

   $token = AsymmetricJwt::issuer(
       $signingKeys['private'],
       type: 'at+jwt',
       keyId: 'auth-2026-08',
   )->issue($claims); // ES256 by default

   $result = AsymmetricJwt::verifier(
       $signingKeys['public'],
       JwtPolicy::oauthAccessToken('https://auth.example.com', 'orders-api'),
   )->verifyResult($token);

   if (!$result->valid) {
       throw new RuntimeException($result->failureReason?->name ?? 'JWT rejected');
   }

Use ``KeyRing`` or ``Jwks`` to resolve a verified ``kid`` during rotation.
The RFC 9068 policy accepts the equivalent ``at+jwt`` and
``application/at+jwt`` media types while rejecting every unrelated type.
Single-use password-reset, email-verification, and action JWT policies require
an atomic ``JwtReplayStoreInterface`` implementation.

Use symmetric JWT inside one trust boundary
-------------------------------------------

All holders of an HMAC key can issue tokens, so HS JWT is appropriate only when
issuer and verifier share one trust boundary.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
   use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;

   $key = SymmetricJwt::generateBinaryKey(); // 64 bytes for default HS512
   $claims = JwtClaims::issue('urn:worker-auth', 'worker-17', ['job-queue'], 120);
   $token = SymmetricJwt::issuer($key, 'at+jwt')->issue($claims);
   $valid = SymmetricJwt::verifier(
       $key,
       JwtPolicy::accessToken('urn:worker-auth', 'job-queue'),
   )->verify($token);

Publish an asymmetric verification key as JWK
----------------------------------------------

``Jwks`` validates that key type, curve or RSA size, metadata, and configured
algorithm agree during export and import.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Jwks;

   $signingKeys = KeyPairGenerator::openSsl(type: OpenSslKeyType::EC)->generate();
   $jwks = new Jwks();
   $publicJwk = $jwks->exportPublicKeyToJwk(
       $signingKeys['public'],
       'auth-2026-08',
       AsymmetricJwtAlgorithm::ES256,
   );
   $verifiedPublicKeyPem = $jwks->importPublicKeyFromJwk(
       $publicJwk,
       AsymmetricJwtAlgorithm::ES256,
   );

For an approved non-default JWT algorithm, pass the same explicit enum to both
the issuer and verifier. A mismatch is rejected; there is no automatic fallback
to the token header's algorithm.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;

   $rsaKeys = KeyPairGenerator::openSsl()->generate();
   $issuer = AsymmetricJwt::issuer(
       $rsaKeys['private'],
       type: 'at+jwt',
       algorithm: AsymmetricJwtAlgorithm::RS384,
   );
   $verifier = AsymmetricJwt::verifier(
       $rsaKeys['public'],
       JwtPolicy::accessToken('https://auth.example.com', 'orders-api'),
       algorithm: AsymmetricJwtAlgorithm::RS384,
   );

Issue and rotate an opaque refresh token
----------------------------------------

``RefreshTokenManager`` owns secure generation, client and optional DPoP
binding, absolute and inactivity expiration, family rotation, reuse response,
and revocation orchestration. The application supplies a durable
``RefreshTokenStoreInterface`` implementation because the consume-and-replace
operation must be one database transaction across every application worker.

The store must place a unique constraint on ``digest``, retain consumed token
records until the grant expires, and lock the current record or use an
equivalent compare-and-swap operation. On reuse it must revoke the complete
family in the same transaction. It must never persist the raw token.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenManager;
   use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRotationStatus;

   // $refreshTokenStore is the application's transactional database adapter.
   $refreshTokens = new RefreshTokenManager($refreshTokenStore);
   $grant = new RefreshTokenGrant(
       id: $authorizationGrantId,
       subject: 'user-42',
       clientId: 'browser-client',
       audiences: ['orders-api'],
       scopes: ['orders:read', 'orders:write'],
       expiresAt: time() + 90 * 24 * 60 * 60,
       dpopKeyThumbprint: $proofKeyThumbprint,
   );
   $refreshToken = $refreshTokens->issue($grant);

   // Return $refreshToken once over TLS; never log it or put it in a URL.
   $rotation = $refreshTokens->rotate(
       $presentedRefreshToken,
       $authenticatedClientId,
       $presentedDpopKeyThumbprint,
       requestedScopes: ['orders:read'],
   );
   if (!$rotation->rotated) {
       if ($rotation->status === RefreshTokenRotationStatus::REUSED) {
           $securityEvents->refreshTokenReuse($authorizationGrantId);
       }

       // Map every failure status to OAuth invalid_grant at the HTTP boundary.
       throw new RuntimeException('Refresh token rejected.');
   }

   $replacementRefreshToken = $rotation->token;
   $authorizedGrant = $rotation->grant; // Mint only equal or narrower access.

On logout, call ``revoke($presentedRefreshToken)``. On password change,
account disablement, or another grant-wide security event, call
``revokeGrant($authorizationGrantId)``. ``CLIENT_MISMATCH`` and
``SENDER_MISMATCH`` do not consume the legitimate token. ``REUSED`` means the
store has already revoked the complete family.

``OpaqueToken`` remains available for isolated high-entropy opaque identifiers.
It enforces 43 to 128 Base64URL characters. Do not use digest comparison alone
as an OAuth refresh-token lifecycle.

See :doc:`token-storage` for the complete public-type inventory, a relational
schema, transaction sequence, status handling, and deployment checklist.

Implement JWT replay and denylist storage
-----------------------------------------

``JwtReplayStoreInterface::consume()`` is an atomic insert-if-absent operation
for single-use JWTs and DPoP proofs. ``isRevoked()`` is a non-consuming lookup
for repeatable but revocable JWTs. A ``DENYLIST`` policy therefore permits
repeated access-token use until the application adds its ``iss`` and ``jti`` to
the shared store; ``SINGLE_USE`` accepts exactly one successful verification.
Both checks occur only after signature, header, claim, and time validation.

Sign short-lived application state
-----------------------------------

``SignedPayload`` authenticates readable claims; it does not encrypt them.
The context keeps checkout state from being accepted as another token type.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Token\Payload\SignedPayload;

   $signingKey = new KeyMaterialGenerator()->forMasterSecret(asBase64Url: false);
   $payloads = new SignedPayload('checkout-state/v1');
   $state = $payloads->encode(
       ['cart_id' => 'cart-1847', 'return_path' => '/checkout/complete'],
       $signingKey,
       ['exp' => time() + 600],
   );
   $claims = $payloads->decode($state, $signingKey);

Epicrypt issuance requires all seven registered claims by default. Generic JWT
verification can use ``JwtPolicy::generic()`` with a smaller explicit required
claim set. Use JWT only when independent verifiers need its standardized claim
and algorithm model; prefer opaque tokens for revocable sessions.

Sign a detached webhook and require multiple signatures
---------------------------------------------------------

``Jws`` supports compact, flattened, and general JSON serialization. Detached
payload bytes are supplied explicitly at verification time. This example
requires both the billing and audit signatures.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Jws;

   $payload = file_get_contents('php://input');
   $detached = Jws::signGeneral($payload, [
       Jws::signer($billingPrivateKey, AsymmetricJwtAlgorithm::PS256, 'billing-2026'),
       Jws::signer($auditPrivateKey, AsymmetricJwtAlgorithm::EDDSA, 'audit-2026'),
   ], detached: true);

   $accepted = Jws::verifyGeneral($detached, [
       Jws::verifier($billingPublicKey, AsymmetricJwtAlgorithm::PS256, 'billing-2026'),
       Jws::verifier($auditPublicKey, AsymmetricJwtAlgorithm::EDDSA, 'audit-2026'),
   ], requiredSignatures: 2, detachedPayload: $payload);

RFC 7797 ``b64=false`` is selected with ``base64Payload: false``. Epicrypt
emits and requires protected ``crit: ["b64"]`` and rejects unknown critical
headers.

Publish and rotate a certificate-bound JWKS
--------------------------------------------

Ordinary JWKS export never contains private or symmetric bytes. Secret-bearing
JWK export is deliberately named and must be treated like the source key.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Jwks;

   $jwks = new Jwks();
   $public = $jwks->exportPublicKeyToJwk(
       $signingPublicKeyPem,
       'auth-2026-09',
       AsymmetricJwtAlgorithm::PS256,
   );
   $bound = $jwks->bindCertificateChain($public, [$leafCertificatePem, $caCertificatePem]);
   $jwks->validateCertificateBinding($bound);
   $publicationDocument = ['keys' => [$bound]];
   $thumbprint = $jwks->thumbprint($bound);
   $thumbprintUri = $jwks->thumbprintUri($bound);

   // An explicit protected backup workflow only; never publish this array.
   $privateBackup = $jwks->exportPrivateKeyToJwk(
       $signingPrivateKeyPem,
       'auth-2026-09',
       AsymmetricJwtAlgorithm::PS256,
       password: $privateKeyPassword,
   );

Resolve remote JWKS with safe rollover
--------------------------------------

The destination comes from trusted application configuration, never ``jku`` or
``x5u`` in a token. Supply any PSR-18 client, PSR-17 request factory, and
optionally a PSR-16 cache. Configure the client to refuse redirects and use
bounded connection/read timeouts.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\RemoteJwks;
   use Infocyph\Epicrypt\Token\Jwt\RemoteJwksConfiguration;

   $keys = new RemoteJwks(
       $psr18Client,
       $psr17RequestFactory,
       new RemoteJwksConfiguration('https://issuer.example'),
       $psr16Cache,
   );
   $verificationKey = $keys->resolve($trustedKid, AsymmetricJwtAlgorithm::PS256);

Unknown ``kid`` performs at most one forced refresh. Cache lifetimes and stale
use are bounded; discovery must return the exact configured issuer.

Encrypt PII and nest a signed JWT
---------------------------------

JWE content encryption is always A256GCM. Key management supports ``dir``,
``A256KW``, ``A256GCMKW``, ``RSA-OAEP-256``, ``ECDH-ES``, and
``ECDH-ES+A256KW``.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Jwe;

   $issuer = new Jwe(
       $recipientRsaPublicKey,
       JweKeyManagementAlgorithm::RSA_OAEP_256,
       keyId: 'pii-recipient-2026',
   );
   $recipient = new Jwe(
       $recipientRsaPrivateKey,
       JweKeyManagementAlgorithm::RSA_OAEP_256,
       keyId: 'pii-recipient-2026',
   );
   $encryptedPii = $issuer->encryptFlattened(json_encode($customerRecord, JSON_THROW_ON_ERROR));
   $customerRecord = json_decode($recipient->decryptFlattened($encryptedPii), true, flags: JSON_THROW_ON_ERROR);

   // Sign first; validate/decrypt the authenticated outer layer before the inner verifier.
   $nested = $issuer->encryptNested($signedAccessToken);
   $innerJws = $recipient->decryptNested($nested);
   $verified = $accessTokenVerifier->verifyResult($innerJws);

Compression, RSA1_5, and header-driven remote retrieval are unsupported. Never
log plaintext, content keys, private keys, or complete JOSE values.

Validate an OpenID Connect login
--------------------------------

Verify the signature and baseline claims first, then apply the OIDC nonce,
authorized-party, authentication-age, and half-hash rules.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
   use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;

   $policy = JwtPolicy::openIdIdToken('https://login.example', 'web-client');
   $result = $idTokenVerifier->verifyResult($idToken); // configured with $policy and PS256
   if (!$result->valid) {
       throw new RuntimeException('ID token signature or baseline claims rejected.');
   }
   new OpenIdIdTokenValidator()->validate(
       $result->claims,
       AsymmetricJwtAlgorithm::PS256,
       'web-client',
       nonce: $nonceFromServerSideLoginSession,
       accessToken: $oauthAccessToken,
       authorizationCode: $authorizationCode,
       maximumAuthenticationAge: 900,
   );

Bind an API request with DPoP
-----------------------------

The client retains the private proof key. The resource server uses a shared
atomic replay store and also checks the access token's ``cnf.jkt``.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\DpopProof;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;

   $dpop = new DpopProof();
   $proof = $dpop->issue(
       'POST',
       'https://api.example/orders',
       $proofPrivateKey,
       $proofPublicJwk,
       AsymmetricJwtAlgorithm::EDDSA,
       accessToken: $accessToken,
       nonce: $serverNonce,
   );
   $verifiedProof = $dpop->verifyResult(
       $proof,
       'POST',
       'https://api.example/orders',
       AsymmetricJwtAlgorithm::EDDSA,
       $atomicReplayStore,
       accessToken: $accessToken,
       nonce: $serverNonce,
   );
   $dpop->validateAccessTokenBinding(
       $verifiedAccessTokenClaims,
       $verifiedProof['publicJwk'],
   );

For a DPoP-bound refresh request, pass
``$verifiedProof['keyThumbprint']`` to ``RefreshTokenManager::rotate()``. The
manager compares it with the grant binding before the store consumes the token.
