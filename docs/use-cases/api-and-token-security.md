# API and Token Security Flow

Use this flow when securing API-to-API or client-to-API authorization tokens.

## Choose the Token Type

- Use `Token\Jwt\SymmetricJwt` for shared-secret issuer/verifier setups.
- Use `Token\Jwt\AsymmetricJwt` for split trust boundaries (private signing key, public verification key).
- Use `Token\Opaque\OpaqueToken` when tokens should be random handles (server-side state lookup).
- Use `Token\Payload\SignedPayload` for lightweight signed payload transport.

## Minimal JWT Example (Asymmetric)

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

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

$token = $jwt->encode([
    'iss' => 'https://auth.example.com',
    'aud' => 'api://orders',
    'sub' => 'user-42',
    'nbf' => time(),
    'exp' => time() + 600,
], $privateKeyPem);
```

## Minimal Opaque Token Example

```php
use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

$opaque = new OpaqueToken();
$token = $opaque->issue(48);
$digest = $opaque->hash($token);
```

## Why This Flow

- JWT classes already enforce algorithm enums and claim validation.
- Opaque tokens avoid overloading bearer tokens with sensitive claim data.

## Avoid

- mixing symmetric and asymmetric key expectations in the same verifier path
- accepting algorithm headers without enforcing expected enum algorithm
