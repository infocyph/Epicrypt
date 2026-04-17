Token Complete Examples
=======================

This page groups ``Token`` examples by token style so you can compare JWT, signed payload, opaque token, and validation helpers in one place.

Create and Verify a Symmetric JWT
---------------------------------

Use this when the issuer and verifier share one secret or a keyed secret set.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
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
       'kid' => 'k2',
   ];

   // Use a key id when the verifier may choose among multiple secrets.
   $symKeys = ['k1' => 'legacy-secret', 'k2' => 'active-secret'];
   $sym = new SymmetricJwt(SymmetricJwtAlgorithm::HS512);
   $symToken = $sym->encode($claims, $symKeys);
   $symVerifier = new SymmetricJwt(
       SymmetricJwtAlgorithm::HS512,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );
   $symPayload = $symVerifier->decode($symToken, $symKeys);
   $symValid = $symVerifier->verify($symToken, $symKeys);

Create and Verify an Asymmetric JWT
-----------------------------------

Use this when one service signs with a private key and others verify with public keys.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
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
       'kid' => 'k2',
   ];

   $rsaA = KeyPairGenerator::openSsl()->generate();
   $rsaB = KeyPairGenerator::openSsl()->generate();
   $privateSet = ['k1' => $rsaA['private'], 'k2' => $rsaB['private']];
   $publicSet = ['k1' => $rsaA['public'], 'k2' => $rsaB['public']];
   $asym = new AsymmetricJwt(null, AsymmetricJwtAlgorithm::RS512);
   $asymToken = $asym->encode($claims, $privateSet);
   $asymVerifier = new AsymmetricJwt(
       null,
       AsymmetricJwtAlgorithm::RS512,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );
   $asymPayload = $asymVerifier->decode($asymToken, $publicSet);
   $asymValid = $asymVerifier->verify($asymToken, $publicSet);

Sign a Small Purpose-Bound Payload
----------------------------------

Use this when you want a lightweight signed payload rather than a full JWT.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Payload\SignedPayload;

   $signedPayload = new SignedPayload('reset_password');
   $payloadToken = $signedPayload->encode(['sub' => 'user-1', 'purpose' => 'reset'], 'payload-secret', ['exp' => time() + 600]);
   $payloadClaims = $signedPayload->decode($payloadToken, 'payload-secret');
   $payloadValid = $signedPayload->verify($payloadToken, 'payload-secret');

Issue an Opaque Token
---------------------

Use this when the token should be random and all state should stay on the server.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

   $opaque = new OpaqueToken();
   $opaqueToken = $opaque->issue(48);
   $opaqueDigest = $opaque->hash($opaqueToken);
   $opaqueValid = $opaque->verify($opaqueToken, $opaqueDigest);

Resolve Keys Explicitly
-----------------------

Use this when you manage key sets and need to pick one key by ``kid``.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\KeyResolver;

   $symKeys = ['k1' => 'legacy-secret', 'k2' => 'active-secret'];
   KeyResolver::validate($symKeys, 'k2');
   $resolved = KeyResolver::resolve($symKeys, 'k2');

Validate Claims Directly
------------------------

Use validator classes when validation needs to be explicit or composable.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\Validation\AudienceValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ClaimValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ExpirationValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\IssuerValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
   use Infocyph\Epicrypt\Token\Jwt\Validation\SubjectValidator;

   $claims = [
       'iss' => 'issuer-service',
       'aud' => 'audience-service',
       'sub' => 'subject-service',
       'nbf' => time(),
       'exp' => time() + 600,
   ];

   $claimValidator = new ClaimValidator();
   $claimValidator->assertRequired($claims, ['iss', 'aud', 'sub', 'nbf', 'exp']);
   $claimValidator->assertStringClaim($claims, 'iss');

   $registered = RegisteredClaims::fromArray($claims);
   (new JwtValidator($registered))->validate($claims);
   (new IssuerValidator())->validate('issuer-service', $claims['iss']);
   (new AudienceValidator())->validate('audience-service', $claims['aud']);
   (new SubjectValidator())->validate('subject-service', $claims['sub']);
   (new ExpirationValidator())->validate($claims['nbf'], $claims['exp']);
