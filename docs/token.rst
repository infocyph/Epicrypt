Token Domain
============

Namespace: ``Infocyph\\Epicrypt\\Token``

Scope
-----

- JWT (symmetric and asymmetric)
- signed payload tokens
- opaque tokens
- claim validation and key resolution

Symmetric JWT
-------------

.. code-block:: php

   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
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

   $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512))->encode($claims, 'super-secret-key');

   $jwt = new SymmetricJwt(
       SymmetricJwtAlgorithm::HS512,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );

   $decoded = $jwt->decode($token, 'super-secret-key');
   $isValid = $jwt->verify($token, 'super-secret-key');

Important
~~~~~~~~~

- ``encode`` requires ``nbf`` and ``exp`` claims.
- ``decode`` requires expected claims (``RegisteredClaims``) in constructor.

Asymmetric JWT
--------------

.. code-block:: php

   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
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

   $token = (new AsymmetricJwt(null, AsymmetricJwtAlgorithm::RS512))->encode($claims, $privateKey);
   $jwt = new AsymmetricJwt(
       null,
       AsymmetricJwtAlgorithm::RS512,
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

Opaque Token
------------

.. code-block:: php

   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

   $opaque = new OpaqueToken();
   $token = $opaque->issue(48);
   $digest = $opaque->hash($token);
   $isValid = $opaque->verify($token, $digest);
