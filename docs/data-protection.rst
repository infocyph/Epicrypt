Data protection
===============

``StringProtector`` and ``EnvelopeProtector`` use one authenticated framing
model with XChaCha20-Poly1305 as the secure default. Applications may
explicitly select another approved ``ProtectionAlgorithm`` when constructing a
protector. Protected strings use
``ep2.<header>.<nonce>.<ciphertext>``. The version, domain, algorithm, key ID,
purpose, creation time, and caller AAD are authenticated. Unprotect operations
require the configured algorithm to match the authenticated algorithm ID.

``FileProtector`` uses authenticated Sodium SecretStream frames and Pathwise 3
for safe file lifecycle operations. Its default chunk size is 64 KiB.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\DataProtection\ProtectionAlgorithm;
   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;

   $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $options = new ProtectionOptions('database-backup', 'tenant=42');
   $files = new FileProtector();
   $files->protect('/data/input.sql', '/data/input.sql.ep2', $key, $options);
   $files->unprotect('/data/input.sql.ep2', '/data/restored.sql', $key, $options);

   $interoperable = new ProtectionOptions('application-value');
   $strings = StringProtector::create(ProtectionAlgorithm::AES_256_GCM);
   $payload = $strings->protect('value', $key, $interoperable);

``FileProtector`` does not use the one-shot AEAD selection. It exclusively uses
XChaCha20-Poly1305 SecretStream because that primitive provides authenticated,
bounded-memory streaming.

Use ``KeyRing`` for managed rotation. Entries are eligible only when status,
purpose, algorithm, validity window, and issuer policy all match.
