Tokens
======

Canonical capability guide for token issuance, verification and rotation-friendly flows.

For full domain-level reference and advanced examples, see :doc:`token`.

This includes:

- Signed payload tokens.
- Opaque tokens.
- Purpose-bound tokens (CSRF, reset, action, remember, verification).
- Key-ring aware verification and rotation helpers.
- JWT result APIs (claims/headers/matched key metadata).
- JWKS/JWK interoperability for asymmetric verification by ``kid``.

Quick Example
-------------

.. code-block:: php

   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;

   $jwt = SymmetricJwt::forProfile(
       SecurityProfile::MODERN,
       new ExpectedJwtClaims(issuer: 'issuer-service', audience: 'audience-service', subject: 'subject-service'),
   );

   $token = $jwt->encode([
       'iss' => 'issuer-service',
       'aud' => 'audience-service',
       'sub' => 'subject-service',
       'nbf' => time(),
       'exp' => time() + 600,
   ], 'super-secret-key');

   $result = $jwt->decodeResult($token, 'super-secret-key');
   $isValid = $result->verified;
