# Epicrypt

[![Security & Standards](https://github.com/infocyph/Epicrypt/actions/workflows/security-standards.yml/badge.svg)](https://github.com/infocyph/Epicrypt/actions/workflows/security-standards.yml)
![Packagist Downloads](https://img.shields.io/packagist/dt/infocyph/Epicrypt?color=green&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2FEpicrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/Epicrypt)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/Epicrypt/php)
![GitHub Code Size](https://img.shields.io/github/languages/code-size/infocyph/Epicrypt)
[![Documentation](https://img.shields.io/badge/Documentation-Epicrypt-blue?logo=readthedocs&logoColor=white)](https://docs.infocyph.com/projects/Epicrypt/)

Epicrypt is a capability-first PHP security toolkit.

It provides focused security building blocks for:

- Certificate / PKI / key exchange
- Crypto primitives
- Token security (JWT, payload, opaque)
- Password and secret protection
- Integrity verification
- Secure generation
- Data protection workflows
- Security utilities (signed URL, CSRF, reset/action tokens)

## Installation

```bash
composer require infocyph/epicrypt
```

## Requirements

- PHP `>=8.4`
- `ext-sodium`, `ext-openssl`, `ext-json`, `ext-hash`

## Usage Examples

### Encrypt and decrypt a string

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())->forAead();
$options = new ProtectionOptions('application-secret');
$protector = StringProtector::create();

$ciphertext = $protector->protect('secret-value', $key, $options);
$plaintext = $protector->unprotect($ciphertext, $key, $options);
```

### Encrypt and decrypt a file

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())->forSecretStream();
$options = new ProtectionOptions('file-backup');
$files = new FileProtector();

$files->protect('/data/plain.txt', '/data/plain.txt.ep2', $key, $options);
$files->unprotect('/data/plain.txt.ep2', '/data/plain.out.txt', $key, $options);
```

### Rotate keys with a key ring

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;

$ring = new KeyRing([
    new KeyRingEntry('2026-01', $oldKey, KeyStatus::FALLBACK, KeyPurpose::DATA_PROTECTION, 'xchacha20-poly1305-ietf'),
    new KeyRingEntry('2026-05', $newKey, KeyStatus::ACTIVE, KeyPurpose::DATA_PROTECTION, 'xchacha20-poly1305-ietf'),
]);

$options = new ProtectionOptions('rotating-data');
$protector = StringProtector::create();
$ciphertext = $protector->protectWithKeyRing('rotating-data', $ring, $options);
$result = $protector->unprotectWithKeyRing($ciphertext, $ring, $options);
```

### Hash, verify and rehash password

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Password\PasswordHasher;

$hasher = new PasswordHasher();
$hash = $hasher->hashPassword('MyStrongPassword!2026');

$isValid = $hasher->verifyPassword('MyStrongPassword!2026', $hash);
$rehash = $hasher->verifyAndRehash('MyStrongPassword!2026', $hash);
```

### Issue and verify CSRF token

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Security\CsrfTokenManager;

$csrf = new CsrfTokenManager('csrf-secret');
$token = $csrf->issueToken('session-1');

$ok = $csrf->verifyToken('session-1', $token);
```

### Generate and verify signed URL

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Security\SignedUrl;

$signed = new SignedUrl('url-secret');
$url = $signed->generate('https://example.com/download', ['file' => 'report.pdf'], time() + 300);

$ok = $signed->verify($url);
```

### Issue and verify JWT (HS512)

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;

$key = SymmetricJwt::generateBinaryKey();
$claims = JwtClaims::issue(
    'issuer-service',
    'user-1',
    ['api'],
    600,
    ['client_id' => 'web-client', 'scope' => 'profile:read'],
);
$token = SymmetricJwt::issuer($key, 'at+jwt')->issue($claims);
$verifier = SymmetricJwt::verifier($key, JwtPolicy::oauthAccessToken('issuer-service', 'api'));
$ok = $verifier->verify($token);
```

### Issue and rotate an OAuth refresh token

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenManager;

// Implement RefreshTokenStoreInterface with one durable database transaction.
$refreshTokens = new RefreshTokenManager($refreshTokenStore);
$refreshToken = $refreshTokens->issue(new RefreshTokenGrant(
    id: 'authorization-grant-42',
    subject: 'user-1',
    clientId: 'web-client',
    audiences: ['api'],
    scopes: ['profile:read', 'orders:read'],
    expiresAt: time() + 90 * 24 * 60 * 60,
));

$rotation = $refreshTokens->rotate(
    $presentedRefreshToken,
    'web-client',
    requestedScopes: ['profile:read'],
);
if (!$rotation->rotated) {
    throw new RuntimeException('Map every failure status to invalid_grant.');
}

$replacementRefreshToken = $rotation->token;
```

The [token storage guide](https://docs.infocyph.com/projects/Epicrypt/token-storage.html)
defines the required schema, atomic rotation sequence, reuse response, DPoP
binding, and revocation behavior. Raw refresh tokens must never be stored.

### Generate certificate with SAN

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;

$pair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_3072)->generate();
$dn = ['commonName' => 'service.example.test'];

$options = new CertificateOptions(
    sanDns: ['service.example.test', 'api.example.test'],
);

$certPem = (new CertificateBuilder())->selfSign($dn, $pair['private'], options: $options);
```

## Security

Do not disclose suspected vulnerabilities in a public issue, discussion or pull request. Review the
[security policy](SECURITY.md), then use [GitHub private vulnerability reporting](https://github.com/infocyph/Epicrypt/security/advisories/new)
to contact the maintainers confidentially.

Epicrypt is protected by [PHPForge](https://github.com/infocyph/PHPForge), an automated quality and security gate covering
tests, static and taint analysis, dependency auditing, architecture checks, and release readiness. Automated controls reduce
risk but do not replace responsible disclosure or manual review.

---

<div align="center">
  <sub><strong>Made with ❤️ for the PHP community</strong></sub><br />
  <sub><a href="LICENSE">MIT Licensed</a></sub><br />
  <a href="https://docs.infocyph.com/projects/Epicrypt/">Documentation</a> •
  <a href="SECURITY.md">Security</a> •
  <a href="CODE_OF_CONDUCT.md">Code of Conduct</a> •
  <a href="CONTRIBUTING.md">Contributing</a><br />
  <span title="Issue templates" aria-label="Issue templates">🗂️</span>
  <a href="https://github.com/infocyph/Epicrypt/issues/new?template=bug_report.yml">Bug</a> •
  <a href="https://github.com/infocyph/Epicrypt/issues/new?template=feature_request.yml">Feature</a> •
  <a href="https://github.com/infocyph/Epicrypt/issues/new?template=docs_improvement.yml">Documentation</a> •
  <a href="https://github.com/infocyph/Epicrypt/issues/new?template=question.yml">Question</a> •
  <a href="https://github.com/infocyph/Epicrypt/issues/new?template=ci_failure.yml">CI failure</a><br />
  <span title="Pull request templates" aria-label="Pull request templates">🔀</span>
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=PULL_REQUEST_TEMPLATE.md">General</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=bug_fix.md">Bug fix</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=feature.md">Feature</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=refactor.md">Refactor</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=performance.md">Performance</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=security_reliability.md">Security &amp; reliability</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=documentation.md">Documentation</a> •
  <a href="https://github.com/infocyph/Epicrypt/compare/main...HEAD?quick_pull=1&amp;template=maintenance.md">Maintenance</a>
</div>
