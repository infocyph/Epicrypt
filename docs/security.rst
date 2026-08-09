Application security
====================

This domain provides purpose-bound application tokens, signed URLs, CSRF
tokens, and policy-aware key rotation. These values authenticate data but do
not make their contents secret.

Create a method- and host-bound download URL
--------------------------------------------

Both generation and verification must use the same options. An allowlist
prevents an attacker from asking the signer to produce a valid URL for an
untrusted host.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\SignedUrl;
   use Infocyph\Epicrypt\Security\SignedUrlOptions;

   $secret = new KeyMaterialGenerator()->forMasterSecret(asBase64Url: false);
   $options = new SignedUrlOptions(
       method: 'GET',
       bindHost: true,
       bindScheme: true,
       allowedHosts: ['downloads.example.com'],
   );
   $signer = new SignedUrl($secret);
   $url = $signer->generate(
       'https://downloads.example.com/report',
       ['file' => 'report-1847.csv'],
       expiresAt: time() + 300,
       options: $options,
   );

   $result = $signer->verifyResult($url, $options);
   if (!$result->verified) {
       throw new RuntimeException($result->expired ? 'Link expired.' : 'Invalid link.');
   }

Protect a browser session from CSRF
-----------------------------------

Issue a token into the rendered form and verify it against the same server-side
session identifier when the form is submitted.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\CsrfTokenManager;

   $secret = new KeyMaterialGenerator()->forMasterSecret(asBase64Url: false);
   $csrf = new CsrfTokenManager($secret, ttlSeconds: 3600);
   $formToken = $csrf->issueToken($sessionId);

   if (!$csrf->verifyToken($sessionId, $submittedToken)) {
       throw new RuntimeException('CSRF validation failed.');
   }

Issue purpose-bound account tokens
----------------------------------

Each helper binds a distinct purpose into the authenticated payload, so a
password-reset token cannot be replayed as an email-verification token.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\ActionToken;
   use Infocyph\Epicrypt\Security\EmailVerificationToken;
   use Infocyph\Epicrypt\Security\PasswordResetToken;
   use Infocyph\Epicrypt\Security\RememberToken;

   $secret = new KeyMaterialGenerator()->forMasterSecret(asBase64Url: false);

   $reset = new PasswordResetToken($secret);
   $resetToken = $reset->issue('user-42');
   $resetAllowed = $reset->verify($resetToken, 'user-42');

   $email = new EmailVerificationToken($secret);
   $emailToken = $email->issue('user-42', 'user@example.com');
   $emailAllowed = $email->verify($emailToken, 'user@example.com');

   $remember = new RememberToken($secret);
   $rememberToken = $remember->issue('user-42', 'device-a7f3');
   $rememberAllowed = $remember->verify($rememberToken, 'user-42', 'device-a7f3');

   $action = new ActionToken($secret);
   $actionToken = $action->issue('user-42', 'delete-account');
   $actionAllowed = $action->verify($actionToken, 'user-42', 'delete-account');

These helpers validate integrity, expiry, and expected claims. Applications
must still enforce single use when the workflow requires it.

Rotate signing keys with a typed KeyRing
----------------------------------------

``KeyRingEntry`` constrains every key by status, purpose, algorithm, validity
window, and optional issuer. Retired and disabled keys are never eligible.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\KeyPurpose;
   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\KeyRingEntry;
   use Infocyph\Epicrypt\Security\KeyRotationHelper;
   use Infocyph\Epicrypt\Security\KeyStatus;

   $keys = new KeyMaterialGenerator();
   $ring = new KeyRing([
       new KeyRingEntry(
           id: 'signing-2026-08',
           key: $keys->forMasterSecret(asBase64Url: false),
           status: KeyStatus::ACTIVE,
           purpose: KeyPurpose::KEY_ROTATION,
           algorithm: 'sha512',
       ),
       new KeyRingEntry(
           id: 'signing-2026-05',
           key: $_ENV['PREVIOUS_SIGNING_KEY'],
           status: KeyStatus::FALLBACK,
           purpose: KeyPurpose::KEY_ROTATION,
           algorithm: 'sha512',
       ),
   ]);

   $rotation = new KeyRotationHelper();
   $signature = $rotation->signWithKeyRing('deployment-manifest-v7', $ring);
   $result = $rotation->verifyResult('deployment-manifest-v7', $signature, $ring);

``$result->matchedKeyId`` identifies the verifier key and
``$result->usedFallbackKey`` tells the application that the signed value should
be renewed under the active key.
