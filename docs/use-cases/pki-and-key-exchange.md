# PKI and Key Exchange Flow

Use this flow for asymmetric interoperability, certificate lifecycle, and shared-secret derivation.

## Choose the Capability

- `Certificate\KeyPairGenerator` for OpenSSL or sodium keypairs.
- `Certificate\KeyExchange` for shared-secret derivation.
- `Certificate\CsrBuilder` for CSR generation.
- `Certificate\CertificateBuilder` for certificate creation/self-signing.
- `Certificate\CertificateParser` for reading certificate fields.

## Backend Selection

`KeyExchange` now supports explicit backend selection with enum selectors:

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
use Infocyph\Epicrypt\Certificate\KeyExchange;

$sodiumExchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
$openSslExchange = KeyExchange::forBackend(KeyExchangeBackend::OPENSSL);
```

Named constructors are still available:

- `KeyExchange::sodium()`
- `KeyExchange::openSsl()`

## Minimal CSR + Certificate Example

```php
use Infocyph\Epicrypt\Certificate\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\CertificateParser;
use Infocyph\Epicrypt\Certificate\CsrBuilder;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

$keys = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();

$dn = [
    'countryName' => 'US',
    'organizationName' => 'Epicrypt',
    'commonName' => 'example.local',
];

$csr = CsrBuilder::openSsl()->build($dn, $keys['private']);
$cert = CertificateBuilder::openSsl()->selfSign($dn, $keys['private'], 365);
$parsed = CertificateParser::openSsl()->parse($cert);
```

## Avoid

- using OpenSSL RSA mode while also passing EC curve selectors
- mixing sodium box/sign key material with OpenSSL PEM keys in one call path
