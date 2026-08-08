Getting started
===============

Epicrypt 2.0 requires PHP 8.4 with Hash, JSON, OpenSSL, and Sodium. Install it
with Composer and generate cryptographic keys; never use memorable secrets.

.. code-block:: bash

   composer require infocyph/epicrypt

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;

   $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $options = new ProtectionOptions('customer-email', 'tenant=42');
   $protector = new StringProtector();

   $protected = $protector->protect('alice@example.test', $key, $options);
   $plaintext = $protector->unprotect($protected, $key, $options);

The purpose and additional authenticated data are security boundaries. Supply
the same values during unprotection and keep key material outside source code.
