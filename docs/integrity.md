# Integrity Domain

Namespace: `Infocyph\\Epicrypt\\Integrity`

## Scope

- string hashing
- file hashing
- digest verification
- timing-safe comparison support
- content fingerprint support

## String Hashing

```php
use Infocyph\Epicrypt\Integrity\StringHasher;

$hasher = new StringHasher('sha256');
$digest = $hasher->hash('payload');
$isValid = $hasher->verify('payload', $digest);
```

### HMAC

```php
$digest = $hasher->hash('payload', ['key' => 'hmac-secret']);
```

### Blake2b

```php
$blake = new StringHasher('blake2b');
$digest = $blake->hash('payload', ['length' => 32]);
```

## File Hashing

```php
use Infocyph\Epicrypt\Integrity\FileHasher;

$fileHasher = new FileHasher('sha256');
$digest = $fileHasher->hash('/path/to/file.txt');
$isValid = $fileHasher->verify('/path/to/file.txt', $digest);
```

