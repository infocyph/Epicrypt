Tokens and JWT
==============

Use ``OpaqueToken`` for refresh tokens. JWT issuers and verifiers are separate,
valid configurations created through named constructors.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
   use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;

   $key = SymmetricJwt::generateBinaryKey();
   $claims = JwtClaims::issue('https://issuer.example', 'user-42', ['api'], 300);
   $token = SymmetricJwt::issuer($key, 'at+jwt')->issue($claims);
   $result = SymmetricJwt::verifier(
       $key,
       JwtPolicy::accessToken('https://issuer.example', 'api'),
   )->verifyResult($token);

The verifier fixes ``alg`` and ``typ``. All seven registered claims are
required and validated. Single-use policies require an atomic
``JwtReplayStoreInterface`` implementation. HMAC minimums are 32, 48, and 64
raw bytes for HS256, HS384, and HS512.
