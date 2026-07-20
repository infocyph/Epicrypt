File Encryption
===============

Use ``FileProtector`` for stream-based file encryption/decryption.
Chunk sizes are bounded from 1 byte through 16 MiB; the default is 8 KiB.
Output is staged in the destination directory and committed only after encryption or decryption succeeds.
Existing destinations use atomic replacement where supported and backup/rollback replacement on Windows.

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
