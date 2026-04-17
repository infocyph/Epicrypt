Web App Security Flow
=====================

Use this flow when building browser-facing apps with forms, sessions, signed links, and account verification steps.

Brief
-----

The ``Security`` domain covers the application-level problems that appear around user journeys. These classes are purpose-built for common web flows, so you do not have to assemble them manually from lower-level crypto and token primitives.

Typical Needs
-------------

- protect forms with CSRF tokens
- issue password reset and email verification tokens
- generate signed links that expire
- remember devices or sessions safely

Start Here
----------

- ``Infocyph\Epicrypt\Security\CsrfTokenManager``
- ``Infocyph\Epicrypt\Security\SignedUrl``
- ``Infocyph\Epicrypt\Security\PasswordResetToken``
- ``Infocyph\Epicrypt\Security\EmailVerificationToken``
- ``Infocyph\Epicrypt\Security\RememberToken``
- ``Infocyph\Epicrypt\Security\ActionToken``

Learn by Example
----------------

Scenario: a web app needs one CSRF token for form posts, one reset token for account recovery, and one signed link for email verification.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\CsrfTokenManager;
   use Infocyph\Epicrypt\Security\PasswordResetToken;
   use Infocyph\Epicrypt\Security\SignedUrl;

   // Keep one app secret per environment.
   $secret = $_ENV['EPICRYPT_APP_SECRET'];

   // 1. Bind the CSRF token to a browser session or server-side session id.
   $csrf = new CsrfTokenManager($secret);
   $csrfToken = $csrf->issueToken('session-123');
   $isCsrfValid = $csrf->verifyToken('session-123', $csrfToken);

   // 2. Issue a short-lived password reset token for one user.
   $reset = new PasswordResetToken($secret, ttlSeconds: 900);
   $resetToken = $reset->issue('user-42');
   $resetClaims = $reset->verify($resetToken);

   // 3. Sign a verification link that expires after 15 minutes.
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

Related Pages
-------------

- For broader ``Security`` API coverage, see :doc:`Security Complete Examples <security-complete-examples>`.
- For password hashing and strength checks used alongside account flows, see :doc:`Password Complete Examples <password-complete-examples>`.

Avoid
-----

- building reset/email/remember flows manually with ad-hoc JWT claims
- sharing the same secret across unrelated environments
