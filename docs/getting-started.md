# Getting Started

## Installation

```bash
composer require infocyph/epicrypt
```

## Requirements

- PHP `8.4+`
- `ext-sodium`
- `ext-openssl`
- `ext-json`
- `ext-mbstring`
- `ext-ctype`
- `ext-simplexml`

## First 5 Minutes

```php
<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())
    ->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

$cipher = new AeadCipher();
$ciphertext = $cipher->encrypt('hello epicrypt', $key, ['aad' => 'demo']);
$plaintext = $cipher->decrypt($ciphertext, $key, ['aad' => 'demo']);

var_dump($plaintext); // "hello epicrypt"
```

## Key Format Notes

Many Epicrypt APIs accept keys as **Base64URL strings** by default.

- If you pass raw binary keys, provide context flags such as:
  - `['key_is_binary' => true]`
  - `['nonce_is_binary' => true]` where relevant

## Domain Overview

- `Certificate`: PKI/certificates/key-exchange/asymmetric interoperability
- `Crypto`: direct crypto primitives (AEAD, secretbox, signatures, MAC)
- `Token`: JWT, payload tokens, opaque tokens
- `Password`: password generation/hashing and wrapped secrets
- `Integrity`: string/file digest and verification helpers
- `Generate`: random/nonce/salt/key/token material generation
- `DataProtection`: string/file/envelope protection flows
- `Security`: signed URLs, CSRF, reset/remember/action verification tokens

## Next

- Read [Architecture](architecture.md) first
- Then jump into the capability guide for your use case

