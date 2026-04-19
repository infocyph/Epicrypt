File and Secret Protection Flow
===============================

Use this flow when protecting data at rest (files, blobs, or serialized secret material).

Brief
-----

Use ``DataProtection`` when you want safe higher-level protection workflows, and use ``Password\Secret`` helpers when you need an explicit wrapped-secret lifecycle for application secrets.

Choose the Capability
---------------------

- Use ``DataProtection\StringProtector`` for app string payloads.
- Use ``DataProtection\FileProtector`` for filesystem encryption/decryption.
- Use ``DataProtection\EnvelopeProtector`` for versioned envelope-based protected payloads.
- Use ``Password\Secret\WrappedSecretManager`` when wrapping/unwrapping secret values under a master key.

Learn by Example
----------------

Scenario: protect a database snapshot on disk and wrap a sensitive application secret with a master key.

Minimal File Protection Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $protector = FileProtector::forProfile(SecurityProfile::MODERN);

   // Generate a stream-safe key for large file protection.
   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);

   $protector->encrypt('/var/app/input.db', '/var/app/input.db.enc', $key, 8192, false);
   $protector->decrypt('/var/app/input.db.enc', '/var/app/input.db', $key, 8192, false);

Minimal Secret Wrapping Example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Scenario: keep a secret encrypted under a master secret before storing it in configuration or persistence.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   $master = (new MasterSecretGenerator())->generate();
   $manager = new WrappedSecretManager();

   $wrapped = $manager->wrap('db-password', $master);
   $plain = $manager->unwrap($wrapped, $master);

Why This Flow
-------------

- DataProtection classes provide higher-level safe workflows on top of crypto primitives.
- Password Secret classes give explicit secret lifecycle behavior instead of ad-hoc encryption calls.

Related Pages
-------------

- For full ``DataProtection`` examples, see :doc:`Data Protection Complete Examples <data-protection-complete-examples>`.
- For password and wrapped-secret helpers, see :doc:`Password Complete Examples <password-complete-examples>`.

Avoid
-----

- encrypting big files using non-streaming single-shot primitives
- reusing nonces manually across encryptions
