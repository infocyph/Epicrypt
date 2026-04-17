Web App Security Flow
=====================

Use this flow when building browser-facing apps (forms, sessions, account verification links).

Typical Needs
-------------

- CSRF tokens
- signed/expiring links
- password reset and email verification tokens
- remember-me tokens

Recommended Classes
-------------------

- ``Infocyph\Epicrypt\Security\CsrfTokenManager``
- ``Infocyph\Epicrypt\Security\SignedUrl``
- ``Infocyph\Epicrypt\Security\PasswordResetToken``
- ``Infocyph\Epicrypt\Security\EmailVerificationToken``
- ``Infocyph\Epicrypt\Security\RememberToken``
- ``Infocyph\Epicrypt\Security\ActionToken``

Minimal Example
---------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\CsrfTokenManager;
   use Infocyph\Epicrypt\Security\PasswordResetToken;
   use Infocyph\Epicrypt\Security\SignedUrl;

   $secret = $_ENV['EPICRYPT_APP_SECRET'];

   $csrf = new CsrfTokenManager($secret);
   $csrfToken = $csrf->issueToken('session-123');
   $isCsrfValid = $csrf->verifyToken('session-123', $csrfToken);

   $reset = new PasswordResetToken($secret, ttlSeconds: 900);
   $resetToken = $reset->issue('user-42');
   $resetClaims = $reset->verify($resetToken);

   $signedUrl = new SignedUrl($secret);
   $link = $signedUrl->generate(
       'https://app.example.com/email/verify',
       ['user' => '42'],
       time() + 900,
   );

Why This Flow
-------------

- Security domain classes already include purpose binding and expiration handling.
- They reduce custom token mistakes for common application workflows.

Avoid
-----

- building reset/email/remember flows manually with ad-hoc JWT claims
- sharing the same secret across unrelated environments
