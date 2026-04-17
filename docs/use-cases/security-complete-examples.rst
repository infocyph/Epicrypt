Security Complete Examples
==========================

This page groups ``Security`` examples around common web application scenes: signed links, CSRF, purpose-bound account tokens, and key rotation.

Generate and Verify a Signed URL
--------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\SignedUrl;

   $signedUrl = new SignedUrl('url-secret');
   $link = $signedUrl->generate('https://example.com/download', ['file' => 'report.csv'], time() + 300);
   $linkValid = $signedUrl->verify($link);

Issue and Verify a CSRF Token
-----------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\CsrfTokenManager;

   $csrf = new CsrfTokenManager('csrf-secret', 3600);
   $csrfToken = $csrf->issueToken('session-123');
   $csrfValid = $csrf->verifyToken('session-123', $csrfToken);

Issue Purpose-Bound Account Tokens
----------------------------------

Use these classes for recovery, verification, remembered devices, and one-off actions.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\ActionToken;
   use Infocyph\Epicrypt\Security\EmailVerificationToken;
   use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
   use Infocyph\Epicrypt\Security\PasswordResetToken;
   use Infocyph\Epicrypt\Security\RememberToken;

   $reset = new PasswordResetToken('token-secret', 1800);
   $resetToken = $reset->issue('user-1');
   $resetValid = $reset->verify($resetToken, 'user-1');

   $email = new EmailVerificationToken('token-secret', 86400);
   $emailToken = $email->issue('user-1', 'user@example.com');
   $emailValid = $email->verify($emailToken, 'user@example.com');

   $remember = new RememberToken('token-secret', 1209600);
   $rememberToken = $remember->issue('user-1', 'device-1');
   $rememberValid = $remember->verify($rememberToken, 'user-1', 'device-1');

   $action = new ActionToken('token-secret', 900);
   $actionToken = $action->issue('user-1', 'delete-account', ['ip' => '203.0.113.10']);
   $actionValid = $action->verify($actionToken, 'user-1', 'delete-account');
   $csrfPurpose = SecurityTokenPurpose::CSRF->value;

Rotate Keys Safely
------------------

Use this when signatures must be accepted during a key rollover window.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\KeyRotationHelper;

   $rotation = new KeyRotationHelper();
   $keys = ['k1' => 'legacy-key', 'k2' => 'active-key'];
   $signature = $rotation->sign('payload', 'k2', $keys);
   $validWithKid = $rotation->verify('payload', $signature, $keys, 'k2');
   $validAgainstWholeSet = $rotation->verify('payload', $signature, $keys);
