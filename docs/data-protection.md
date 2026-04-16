# Data Protection Domain

Namespace: `Infocyph\\Epicrypt\\DataProtection`

## Scope

Higher-level security workflows built on crypto primitives:

- string protection
- file protection
- envelope encryption
- OpenSSL interoperability helper

## String Protector

```php
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

$protector = new StringProtector();
$ciphertext = $protector->encrypt('sensitive data', $key);
$plaintext = $protector->decrypt($ciphertext, $key);
```

## Envelope Protector

```php
use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$masterKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
$envelope = (new EnvelopeProtector())->encrypt('payload', $masterKey);

$encoded = (new EnvelopeProtector())->encodeEnvelope($envelope);
$plain = (new EnvelopeProtector())->decrypt($encoded, $masterKey);
```

Envelope payload includes:

- `v` format version
- `alg` algorithm marker
- `encrypted_data`
- `encrypted_key`

## File Protector

```php
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

$key = (new KeyMaterialGenerator())
    ->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);

$file = new FileProtector();
$file->encrypt('/tmp/input.txt', '/tmp/input.txt.epc', $key);
$file->decrypt('/tmp/input.txt.epc', '/tmp/input.dec.txt', $key);
```

## OpenSSL Interoperability Helper

`DataProtection\\OpenSSL\\InteroperabilityCryptoHelper` provides a compatibility-oriented string encryption format using OpenSSL + HMAC.

