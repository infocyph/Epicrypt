# Security Domain

Namespace: `Infocyph\\Epicrypt\\Security`

## Scope

- signed URLs
- CSRF token management
- password reset tokens
- email verification tokens
- remember tokens
- action tokens
- key rotation helper

## Signed URLs

```php
use Infocyph\Epicrypt\Security\SignedUrl;

$signed = new SignedUrl('url-secret');
$url = $signed->generate('https://example.com/download', ['file' => 'report.csv'], time() + 300);

$isValid = $signed->verify($url);
```

## CSRF

```php
use Infocyph\Epicrypt\Security\CsrfTokenManager;

$csrf = new CsrfTokenManager('csrf-secret', 3600);
$token = $csrf->issueToken('session-id');
$isValid = $csrf->verifyToken('session-id', $token);
```

## Purpose-Bound Tokens

```php
use Infocyph\Epicrypt\Security\PasswordResetToken;
use Infocyph\Epicrypt\Security\EmailVerificationToken;
use Infocyph\Epicrypt\Security\RememberToken;
use Infocyph\Epicrypt\Security\ActionToken;

$reset = new PasswordResetToken('token-secret', 1800);
$resetToken = $reset->issue('user-1');
$resetOk = $reset->verify($resetToken, 'user-1');

$email = new EmailVerificationToken('token-secret', 86400);
$emailToken = $email->issue('user-1', 'user@example.com');
$emailOk = $email->verify($emailToken, 'user@example.com');

$remember = new RememberToken('token-secret', 1209600);
$rememberToken = $remember->issue('user-1', 'device-1');
$rememberOk = $remember->verify($rememberToken, 'user-1', 'device-1');

$action = new ActionToken('token-secret', 900);
$actionToken = $action->issue('user-1', 'delete-account');
$actionOk = $action->verify($actionToken, 'user-1', 'delete-account');
```

## Key Rotation Helper

```php
use Infocyph\Epicrypt\Security\KeyRotationHelper;

$keys = [
    'k1' => 'legacy-key',
    'k2' => 'active-key',
];

$rotation = new KeyRotationHelper();
$signature = $rotation->sign('payload', 'k2', $keys);

$isValidWithKid = $rotation->verify('payload', $signature, $keys, 'k2');
$isValidAgainstSet = $rotation->verify('payload', $signature, $keys);
```

