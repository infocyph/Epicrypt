# Epicrypt

[![Security & Standards](https://github.com/infocyph/Epicrypt/actions/workflows/security-standards.yml/badge.svg)](https://github.com/infocyph/Epicrypt/actions/workflows/security-standards.yml)
[![Documentation](https://img.shields.io/badge/Documentation-Epicrypt-blue?logo=readthedocs&logoColor=white)](https://docs.infocyph.com/projects/Epicrypt/)
![Packagist Downloads](https://img.shields.io/packagist/dt/infocyph/Epicrypt?color=green&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2FEpicrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/Epicrypt)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/Epicrypt/php)
![GitHub Code Size](https://img.shields.io/github/languages/code-size/infocyph/Epicrypt)

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
- `ext-sodium`, `ext-openssl`, `ext-json`, `ext-mbstring`, `ext-hash`

## Usage Examples

### Encrypt and decrypt a string

```php
<?php

use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())->forSecretBox();
$protector = new StringProtector();

$ciphertext = $protector->encrypt('secret-value', $key);
$plaintext = $protector->decrypt($ciphertext, $key);
```

### Encrypt and decrypt a file

```php
<?php

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())->forSecretStream();
$files = new FileProtector();

$files->encrypt('/data/plain.txt', '/data/plain.txt.epc', $key);
$files->decrypt('/data/plain.txt.epc', '/data/plain.out.txt', $key);
```

### Rotate keys with a key ring

```php
<?php

use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Security\KeyRing;

$ring = new KeyRing([
    '2026-01' => $oldKey,
    '2026-05' => $newKey,
], '2026-05');

$protector = new StringProtector();
$ciphertext = $protector->encryptWithKeyRing('rotating-data', $ring);
$result = $protector->decryptWithKeyRingResult($ciphertext, $ring);
```

### Hash, verify and rehash password

```php
<?php

use Infocyph\Epicrypt\Password\PasswordHasher;

$hasher = new PasswordHasher();
$hash = $hasher->hashPassword('MyStrongPassword!2026');

$isValid = $hasher->verifyPassword('MyStrongPassword!2026', $hash);
$rehash = $hasher->verifyAndRehash('MyStrongPassword!2026', $hash);
```

### Issue and verify CSRF token

```php
<?php

use Infocyph\Epicrypt\Security\CsrfTokenManager;

$csrf = new CsrfTokenManager('csrf-secret');
$token = $csrf->issueToken('session-1');

$ok = $csrf->verifyToken('session-1', $token);
```

### Generate and verify signed URL

```php
<?php

use Infocyph\Epicrypt\Security\SignedUrl;

$signed = new SignedUrl('url-secret');
$url = $signed->generate('https://example.com/download', ['file' => 'report.pdf'], time() + 300);

$ok = $signed->verify($url);
```

### Issue and verify JWT (HS512)

```php
<?php

use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

$issuer = new SymmetricJwt(SymmetricJwtAlgorithm::HS512);
$token = $issuer->encode([
    'iss' => 'issuer-service',
    'aud' => 'api',
    'sub' => 'user-1',
    'jti' => 'jwt-1',
    'nbf' => time(),
    'exp' => time() + 600,
], 'signing-secret');

$verifier = new SymmetricJwt(
    SymmetricJwtAlgorithm::HS512,
    new RegisteredClaims('issuer-service', 'api', 'user-1', 'jwt-1'),
);

$ok = $verifier->verify($token, 'signing-secret');
```

### Generate certificate with SAN

```php
<?php

use Infocyph\Epicrypt\Certificate\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

$pair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_3072)->generate();
$dn = ['commonName' => 'service.example.test'];

$options = new CertificateOptions(
    sanDns: ['service.example.test', 'api.example.test'],
);

$certPem = CertificateBuilder::openSsl()->selfSign($dn, $pair['private'], options: $options);
```

## Security

Protected by [PHPForge](https://github.com/infocyph/PHPForge) — an automated quality and security gate for PHP projects.

---

<div align="center">
  <sub><strong>Made with ❤️ for the PHP community</strong></sub><br />
  <sub><a href="LICENSE">MIT Licensed</a></sub><br />
  <a href="https://docs.infocyph.com/projects/Epicrypt">Documentation</a> •
  <a href="SECURITY.md">Security</a> •
  <a href="CODE_OF_CONDUCT.md">Code of Conduct</a> •
  <a href="CONTRIBUTING.md">Contributing</a> •
  <a href="https://github.com/infocyph/Epicrypt/issues">Report | Request | Suggest</a>
</div>
