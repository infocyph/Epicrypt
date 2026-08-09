Data protection
===============

``StringProtector`` and ``EnvelopeProtector`` default to
XChaCha20-Poly1305 and also support explicit AES-256-GCM selection on platforms
where Sodium reports hardware support. Both use the common authenticated
``ep2`` framing model. The version, domain, algorithm identifier, key ID,
purpose, creation time, and caller AAD are authenticated.

``FileProtector`` exclusively uses authenticated XChaCha20-Poly1305
SecretStream, the appropriate bounded-memory primitive for files. Its default
chunk size is 64 KiB.

Protect a database field
------------------------

The stable purpose prevents a ciphertext created for one application feature
from being accepted by another. Bind immutable record identity as AAD; the same
bytes must be supplied during unprotection.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = new KeyMaterialGenerator()->forAead();
   $options = new ProtectionOptions(
       purpose: 'customer/tax-id/v1',
       additionalAuthenticatedData: 'tenant=42;customer=1847',
   );

   $protector = StringProtector::create(); // XChaCha20-Poly1305
   $storedValue = $protector->protect('123-45-6789', $key, $options);
   $taxId = $protector->unprotect($storedValue, $key, $options);

Use envelope protection for independently generated data keys
-------------------------------------------------------------

``EnvelopeProtector`` generates a fresh data-encryption key per payload and
protects that key with the master key. This is appropriate for larger records
or architectures that distinguish master keys from data keys.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $masterKey = new KeyMaterialGenerator()->forMasterSecret();
   $options = new ProtectionOptions(
       purpose: 'insurance/application/v1',
       additionalAuthenticatedData: 'application=APP-1048',
   );

   $protector = EnvelopeProtector::create(); // XChaCha20-Poly1305
   $envelope = $protector->protect($applicationJson, $masterKey, $options);
   $restoredJson = $protector->unprotect($envelope, $masterKey, $options);

Protect a database backup without loading it into memory
--------------------------------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = new KeyMaterialGenerator()->forSecretStream();
   $options = new ProtectionOptions(
       purpose: 'database-backup/v1',
       additionalAuthenticatedData: 'cluster=primary;date=2026-08-09',
   );

   $files = new FileProtector();
   $files->protect('/backups/db.sql', '/backups/db.sql.ep2', $key, $options);
   $files->unprotect('/backups/db.sql.ep2', '/restore/db.sql', $key, $options);

The destination is staged and committed only after the complete operation
succeeds. Input and output paths must differ.

Rotate keys with policy metadata
--------------------------------

Use ``KeyRing`` when ciphertext must carry a key ID and old keys remain
readable during a rotation window. Exactly one eligible active key is required
for writes.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionAlgorithm;
   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\KeyPurpose;
   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\KeyRingEntry;
   use Infocyph\Epicrypt\Security\KeyStatus;

   $keys = new KeyMaterialGenerator();
   $algorithm = ProtectionAlgorithm::XCHACHA20_POLY1305;
   $ring = new KeyRing([
       new KeyRingEntry(
           id: 'dp-2026-08',
           key: $keys->generate($algorithm->keyLength()),
           status: KeyStatus::ACTIVE,
           purpose: KeyPurpose::DATA_PROTECTION,
           algorithm: $algorithm->value,
       ),
       new KeyRingEntry(
           id: 'dp-2026-05',
           key: $_ENV['PREVIOUS_DATA_PROTECTION_KEY'],
           status: KeyStatus::FALLBACK,
           purpose: KeyPurpose::DATA_PROTECTION,
           algorithm: $algorithm->value,
       ),
   ]);

   $options = new ProtectionOptions('customer/tax-id/v1', 'tenant=42;customer=1847');
   $protector = StringProtector::create();
   $payload = $protector->protectWithKeyRing('123-45-6789', $ring, $options);
   $result = $protector->unprotectWithKeyRing($payload, $ring, $options);

``$result->keyId`` identifies the key used to read the payload. Applications
can use that identifier to decide whether to renew the value under the active
key.

Explicit algorithm selection
----------------------------

Defaults should be used unless interoperability requires otherwise. Selection
is explicit and the authenticated payload algorithm must match the configured
protector.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionAlgorithm;
   use Infocyph\Epicrypt\DataProtection\StringProtector;

   $aesProtector = StringProtector::create(ProtectionAlgorithm::AES_256_GCM);

There is intentionally no algorithm selector on ``FileProtector``.
