Security Domain
===============

Namespace: ``Infocyph\\Epicrypt\\Security``

Scope
-----

- signed URLs
- CSRF token management
- password reset tokens
- email verification tokens
- remember tokens
- action tokens
- key rotation helper
- key-ring metadata for rotation windows and purpose-scoped key usage

Signed URLs
-----------

.. code-block:: php

   use Infocyph\Epicrypt\Security\SignedUrl;
   use Infocyph\Epicrypt\Security\SignedUrlOptions;

   $signed = new SignedUrl('url-secret');
   $options = new SignedUrlOptions(
       method: 'GET',
       bindHost: true,
       bindScheme: true,
       allowArrayParameters: false,
       allowedHosts: ['example.com'],
   );

   $url = $signed->generate('https://example.com/download', ['file' => 'report.csv'], time() + 300, $options);

   $isValid = $signed->verify($url);
   $result = $signed->verifyResult($url, $options);

``verifyResult()`` exposes ``verified``, ``expired``, ``invalidSignature``, ``expiresAt`` and ``version``.

CSRF
----

.. code-block:: php

   use Infocyph\Epicrypt\Security\CsrfTokenManager;

   $csrf = new CsrfTokenManager('csrf-secret', 3600);
   $token = $csrf->issueToken('session-id');
   $isValid = $csrf->verifyToken('session-id', $token);

Purpose-Bound Tokens
--------------------

.. code-block:: php

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

Key Rotation Helper
-------------------

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRotationHelper;

   $keys = [
       'k1' => 'previous-key',
       'k2' => 'active-key',
   ];

   $rotation = new KeyRotationHelper();
   $signature = $rotation->sign('payload', 'k2', $keys);

   $isValidWithKid = $rotation->verify('payload', $signature, $keys, 'k2');
   $isValidAgainstSet = $rotation->verify('payload', $signature, $keys);
   $result = $rotation->verifyResult('payload', $signature, $keys);

``verifyResult()`` returns ``KeyVerificationResult`` with ``verified``, ``matchedKeyId`` and ``usedFallbackKey``.

KeyRing Metadata
----------------

Use metadata entries when keys have status, validity windows or scope constraints.

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRing;

   $ring = new KeyRing([
       'k2026-05' => [
           'key' => 'active-key',
           'status' => KeyRing::STATUS_ACTIVE,
           'not_before' => 1767225600,
           'not_after' => 1798761600,
           'purpose' => 'jwt-signing',
       ],
       'k2025-12' => [
           'key' => 'fallback-key',
           'status' => KeyRing::STATUS_FALLBACK,
           'purpose' => 'jwt-signing',
       ],
   ], 'k2026-05');

   $activeKey = $ring->activeKey();
   $ordered = $ring->orderedEntries('jwt-signing', time());
