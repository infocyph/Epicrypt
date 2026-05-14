Token Domain
============

Namespace: ``Infocyph\\Epicrypt\\Token``

Scope
-----

- JWT (symmetric and asymmetric)
- signed payload tokens
- opaque tokens
- claim validation and key resolution
- key-ring verification helpers for signed payload and JWT rotation
- JWKS/JWK export, import, and kid-based verification flows
- structured verification result objects for safer application decisions

Symmetric JWT
-------------

.. code-block:: php

   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

   $now = time();
   $claims = [
       'iss' => 'issuer-service',
       'aud' => 'audience-service',
       'sub' => 'subject-service',
       'jti' => 'token-1',
       'nbf' => $now,
       'exp' => $now + 600,
       'scope' => 'admin',
   ];

   $token = SymmetricJwt::forProfile(SecurityProfile::MODERN)->encode($claims, 'super-secret-key');

   $jwt = SymmetricJwt::forProfile(
       SecurityProfile::MODERN,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );

   $decoded = $jwt->decode($token, 'super-secret-key');
   $isValid = $jwt->verify($token, 'super-secret-key');

Important
~~~~~~~~~

- ``encode`` requires ``nbf`` and ``exp`` claims.
- ``decode`` requires expected claims (``RegisteredClaims``) in constructor.

JWT Key Rings
-------------

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

   $jwt = SymmetricJwt::forProfile(
       SecurityProfile::MODERN,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );

   $ring = new KeyRing(['previous' => 'previous-secret', 'active' => 'active-secret'], 'active');
   $claims = $jwt->decodeWithAnyKey($token, $ring);
   $isValid = $jwt->verifyWithAnyKey($token, $ring);
   $result = $jwt->verifyWithAnyKeyResult($token, $ring);

Asymmetric JWT
--------------

.. code-block:: php

   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $keys = KeyPairGenerator::openSsl()->generate();
   $privateKey = $keys['private'];
   $publicKey = $keys['public'];

   $now = time();
   $claims = [
       'iss' => 'issuer-service',
       'aud' => 'audience-service',
       'sub' => 'subject-service',
       'jti' => 'token-1',
       'nbf' => $now,
       'exp' => $now + 600,
   ];

   $token = AsymmetricJwt::forProfile(SecurityProfile::MODERN)->encode($claims, $privateKey);
   $jwt = AsymmetricJwt::forProfile(
       SecurityProfile::MODERN,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );
   $isValid = $jwt->verify($token, $publicKey);

JWT Result APIs
---------------

Use result APIs when you need structured verification state instead of only boolean pass/fail.

.. code-block:: php

   use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RequiredJwtClaims;
   use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidationOptions;

   $jwt = SymmetricJwt::forProfile(
       SecurityProfile::MODERN,
       new ExpectedJwtClaims(
           issuer: 'issuer-service',
           audience: 'audience-service',
           subject: 'subject-service',
           required: new RequiredJwtClaims(issuer: true, audience: true, subject: true),
       ),
       new JwtValidationOptions(strictTyp: true, leewaySeconds: 15),
   );

   $result = $jwt->decodeResult($token, 'super-secret-key');
   if ($result->verified) {
       $claims = $result->claims;
       $headers = $result->headers;
   }

   // Metadata fields:
   // $result->matchedKeyId
   // $result->usedFallbackKey
   // $result->expired
   // $result->notBeforeViolation
   // $result->algorithm

Signed Payload Token
--------------------

.. code-block:: php

   use Infocyph\Epicrypt\Token\Payload\SignedPayload;

   $payload = new SignedPayload('reset_password');

   $token = $payload->encode(
       ['sub' => 'user-1', 'purpose' => 'reset'],
       'payload-secret',
       ['exp' => time() + 600],
   );

   $claims = $payload->decode($token, 'payload-secret');
   $isValid = $payload->verify($token, 'payload-secret');

Signed Payload Key Rings
------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Token\Payload\SignedPayload;

   $payload = new SignedPayload('reset_password');
   $ring = new KeyRing(['previous' => 'previous-secret', 'active' => 'active-secret'], 'active');
   $claims = $payload->decodeWithAnyKey($token, $ring);
   $isValid = $payload->verifyWithAnyKey($token, $ring);
   $result = $payload->verifyWithAnyKeyResult($token, $ring);
   $detailed = $payload->verifyWithAnyKeyDetailedResult($token, $ring);

Signed Payload Result APIs
--------------------------

.. code-block:: php

   $result = $payload->verifyResult($token, 'payload-secret');
   if ($result->verified) {
       $claims = $result->claims;
   }

   // Metadata fields:
   // $result->matchedKeyId
   // $result->usedFallbackKey
   // $result->expired

Opaque Token
------------

.. code-block:: php

   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

   $opaque = new OpaqueToken();
   $token = $opaque->issue(48);
   $digest = $opaque->hash($token);
   $isValid = $opaque->verify($token, $digest);

JWKS/JWK Interoperability
-------------------------

Use this for asymmetric JWT interop where verifier keys are distributed in JWKS form.

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Jwks;

   $jwksHelper = new Jwks();
   $publicRing = new KeyRing(['k1' => $publicKey1, 'k2' => $publicKey2], 'k2');
   $jwks = $jwksHelper->exportFromKeyRing($publicRing);

   // Resolve by kid to PEM:
   $pem = $jwksHelper->resolvePublicKeyByKid($jwks, 'k2');

   // Verify directly from JWKS:
   $jwt = AsymmetricJwt::forProfile(SecurityProfile::MODERN, $expectedClaims);
   $result = $jwt->verifyFromJwksResult($token, $jwks);
   $isValid = $result->verified;
