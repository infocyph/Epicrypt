File Encryption
===============

Use ``FileProtector`` for stream-based file encryption/decryption.

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->forSecretStream();
   $files = new FileProtector();

   $files->encrypt('/data/plain.txt', '/data/plain.txt.epc', $key);
   $files->decrypt('/data/plain.txt.epc', '/data/plain.out.txt', $key);

Rotation helpers:

- ``reencrypt()``
- ``reencryptWithAnyKey()``
- ``reencryptInPlaceWithAnyKey()``

