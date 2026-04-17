File and Secret Protection Flow
===============================

Use this flow when protecting data at rest (files, blobs, or serialized secret material).

Choose the Capability
---------------------

- Use ``DataProtection\StringProtector`` for app string payloads.
- Use ``DataProtection\FileProtector`` for filesystem encryption/decryption.
- Use ``DataProtection\EnvelopeProtector`` for versioned envelope-based protected payloads.
- Use ``Password\Secret\WrappedSecretManager`` when wrapping/unwrapping secret values under a master key.

Minimal File Protection Example
-------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $protector = new FileProtector();
   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);

   $protector->encrypt('/var/app/input.db', '/var/app/input.db.enc', $key, 8192, false);

   $protector->decrypt('/var/app/input.db.enc', '/var/app/input.db', $key, 8192, false);

Minimal Secret Wrapping Example
-------------------------------

.. code-block:: php

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

Avoid
-----

- encrypting big files using non-streaming single-shot primitives
- reusing nonces manually across encryptions
