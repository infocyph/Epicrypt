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

   $resource = openssl_pkey_new([
       'private_key_type' => OPENSSL_KEYTYPE_RSA,
       'private_key_bits' => 2048,
   ]);
   openssl_pkey_export($resource, $privateKey);
   $details = openssl_pkey_get_details($resource);
   $publicKey = $details['key'];

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

Opaque Token
------------

.. code-block:: php

   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

   $opaque = new OpaqueToken();
   $token = $opaque->issue(48);
   $digest = $opaque->hash($token);
   $isValid = $opaque->verify($token, $digest);
