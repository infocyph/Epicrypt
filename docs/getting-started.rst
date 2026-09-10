Getting started
===============

Epicrypt 3.0 requires PHP 8.4 or later with Hash, JSON, OpenSSL, and Sodium.
Install it with Composer and generate cryptographic key material with Epicrypt's
CSPRNG-backed generators; never derive production keys from memorable secrets.

.. code-block:: bash

   composer require infocyph/epicrypt

Protect and recover an application value
----------------------------------------

Use a stable purpose for the data class and bind immutable record context as
additional authenticated data (AAD). The same purpose and AAD must be supplied
during unprotection.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   // Provision once and keep this value in a deployment secret manager.
   $key = new KeyMaterialGenerator()->forAead();
   $options = new ProtectionOptions(
       purpose: 'customer/email/v1',
       additionalAuthenticatedData: 'tenant=42;customer=1847',
   );
   $protector = StringProtector::create();

   $protected = $protector->protect('alice@example.test', $key, $options);
   $plaintext = $protector->unprotect($protected, $key, $options);

The purpose and AAD are authenticated security boundaries, not secret storage.
Keep keys outside source control and logs, and use :doc:`data-protection` when
you need rotation, file streaming, or envelope protection.

Choose the right capability
---------------------------

- :doc:`data-protection` for application data encryption and key rotation;
- :doc:`password` for password hashing, verification, and transparent rehash;
- :doc:`token` for JWT/JWS/JWE and generic token mechanics;
- :doc:`oauth-lifecycle` for OAuth 2.1 and OpenID Connect provider mechanics;
- :doc:`personal-access-tokens` for stateful personal/API-token issue,
  authorization, usage tracking, and revocation;
- :doc:`certificate` for PKI, certificates, and authenticated key exchange;
- :doc:`security` for signed URLs, CSRF, reset/action tokens, and key rotation.

Applications supply transport, durable persistence adapters, rate limiting,
audit, sessions, and business authorization policy around Epicrypt's public
security contracts.
