Security Complete Examples
==========================

This page groups ``Security`` examples around common web application scenes: signed links, CSRF, purpose-bound account tokens, and key rotation.

Generate and Verify a Signed URL
--------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\SignedUrl;
   use Infocyph\Epicrypt\Security\SignedUrlOptions;

   $signedUrl = new SignedUrl('url-secret');
   $options = new SignedUrlOptions(method: 'GET', allowedHosts: ['example.com']);
   $link = $signedUrl->generate('https://example.com/download', ['file' => 'report.csv'], time() + 300, $options);
   $linkValid = $signedUrl->verify($link, $options);
   $verifyResult = $signedUrl->verifyResult($link, $options);

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
   $keys = ['k1' => 'previous-key', 'k2' => 'active-key'];
   $signature = $rotation->sign('payload', 'k2', $keys);
   $validWithKid = $rotation->verify('payload', $signature, $keys, 'k2');
   $validAgainstWholeSet = $rotation->verify('payload', $signature, $keys);
   $verifyResult = $rotation->verifyResult('payload', $signature, $keys);

Use KeyRing Metadata
--------------------

Use this when key lifetimes or purpose scope must be enforced by the key set.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\KeyRing;

   $ring = new KeyRing([
       'k-current' => [
           'key' => 'active-key',
           'status' => KeyRing::STATUS_ACTIVE,
           'not_before' => time() - 60,
           'not_after' => time() + 86400,
           'purpose' => 'signed-url',
       ],
       'k-previous' => [
           'key' => 'fallback-key',
           'status' => KeyRing::STATUS_FALLBACK,
           'purpose' => 'signed-url',
       ],
   ], 'k-current');

   $orderedForPurpose = $ring->orderedEntries('signed-url', time());
