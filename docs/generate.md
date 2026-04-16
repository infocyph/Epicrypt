# Generate Domain

Namespace: `Infocyph\\Epicrypt\\Generate`

## Scope

- random bytes
- random strings
- nonces
- salts
- key material
- token material

## Random Bytes and Strings

```php
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;

$random = new RandomBytesGenerator();
$bytes = $random->bytes(32);
$string = $random->string(40, prefix: 'ep_', postfix: '_v1');
```

## Nonce and Salt

```php
use Infocyph\Epicrypt\Generate\NonceGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;

$nonce = (new NonceGenerator())->generate();
$salt = (new SaltGenerator())->generate();
```

## Key and Token Material

```php
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;

$keyMaterial = (new KeyMaterialGenerator())->generate(32); // Base64URL by default
$tokenMaterial = (new TokenMaterialGenerator())->generate(48);
```

