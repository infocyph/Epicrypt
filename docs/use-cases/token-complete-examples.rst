Token Complete Examples
=======================

This page contains complete usage examples for ``Token`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\KeyResolver;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ClaimValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\AudienceValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ExpirationValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\IssuerValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
   use Infocyph\Epicrypt\Token\Jwt\Validation\SubjectValidator;
   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;
   use Infocyph\Epicrypt\Token\Payload\SignedPayload;

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

   // Symmetric JWT with key-set mode (kid required when key is array/ArrayAccess)
   $symKeys = ['k1' => 'legacy-secret', 'k2' => 'active-secret'];
   $sym = new SymmetricJwt(SymmetricJwtAlgorithm::HS512);
   $symToken = $sym->encode($claims, $symKeys);
   $symVerifier = new SymmetricJwt(
       SymmetricJwtAlgorithm::HS512,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );
   $symPayload = $symVerifier->decode($symToken, $symKeys);
   $symValid = $symVerifier->verify($symToken, $symKeys);

   // Asymmetric JWT with kid + key-set
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

   // SignedPayload
   $signedPayload = new SignedPayload('reset_password');
   $payloadToken = $signedPayload->encode(['sub' => 'user-1', 'purpose' => 'reset'], 'payload-secret', ['exp' => time() + 600]);
   $payloadClaims = $signedPayload->decode($payloadToken, 'payload-secret');
   $payloadValid = $signedPayload->verify($payloadToken, 'payload-secret');

   // OpaqueToken
   $opaque = new OpaqueToken();
   $opaqueToken = $opaque->issue(48);
   $opaqueDigest = $opaque->hash($opaqueToken);
   $opaqueValid = $opaque->verify($opaqueToken, $opaqueDigest);

   // KeyResolver utilities
   KeyResolver::validate($symKeys, 'k2');
   $resolved = KeyResolver::resolve($symKeys, 'k2');

   // Claim validators
   $claimValidator = new ClaimValidator();
   $claimValidator->assertRequired($claims, ['iss', 'aud', 'sub', 'nbf', 'exp']);
   $claimValidator->assertStringClaim($claims, 'iss');

   $registered = RegisteredClaims::fromArray($claims);
   (new JwtValidator($registered))->validate($claims);
   (new IssuerValidator())->validate('issuer-service', $claims['iss']);
   (new AudienceValidator())->validate('audience-service', $claims['aud']);
   (new SubjectValidator())->validate('subject-service', $claims['sub']);
   (new ExpirationValidator())->validate($claims['nbf'], $claims['exp']);
