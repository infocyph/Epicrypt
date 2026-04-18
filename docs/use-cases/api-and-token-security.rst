API and Token Security Flow
===========================

Use this flow when securing API-to-API or client-to-API authorization tokens.

Brief
-----

The ``Token`` domain helps you choose the right token shape for the trust boundary you have. Start with the token type, then move to validation and key management details.

Choose the Token Type
---------------------

- Use ``Token\Jwt\SymmetricJwt`` for shared-secret issuer/verifier setups.
- Use ``Token\Jwt\AsymmetricJwt`` for split trust boundaries (private signing key, public verification key).
- Use ``Token\Opaque\OpaqueToken`` when tokens should be random handles (server-side state lookup).
- Use ``Token\Payload\SignedPayload`` for lightweight signed payload transport.

Learn by Example
----------------

Scenario: an auth service signs JWTs with a private key and an API verifies them with a public key.

Minimal JWT Example (Asymmetric)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

   // Define the claims your verifier expects.
   $claims = new RegisteredClaims(
       issuer: 'https://auth.example.com',
       audience: 'api://orders',
       subject: 'user-42',
   );

   $jwt = new AsymmetricJwt(
       passphrase: null,
       algorithm: AsymmetricJwtAlgorithm::RS512,
       expectedClaims: $claims,
   );

   // The private key stays on the issuer side only.
   $token = $jwt->encode([
       'iss' => 'https://auth.example.com',
       'aud' => 'api://orders',
       'sub' => 'user-42',
       'nbf' => time(),
       'exp' => time() + 600,
   ], $privateKeyPem);

Minimal Opaque Token Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Scenario: you want a revocable bearer token whose meaning stays in server-side storage.

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

   $opaque = new OpaqueToken();
   $token = $opaque->issue(48);
   $digest = $opaque->hash($token);

Why This Flow
-------------

- JWT classes already enforce algorithm enums and claim validation.
- JWT and signed payload flows support key-ring-based verification during rotation windows.
- Opaque tokens avoid overloading bearer tokens with sensitive claim data.

Related Pages
-------------

- For the full ``Token`` surface area, see :doc:`Token Complete Examples <token-complete-examples>`.
- If the token is for browser workflows rather than APIs, see :doc:`Web App Security <web-app-security>`.

Avoid
-----

- mixing symmetric and asymmetric key expectations in the same verifier path
- accepting algorithm headers without enforcing expected enum algorithm
