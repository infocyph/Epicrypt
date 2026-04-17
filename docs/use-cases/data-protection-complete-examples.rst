Data Protection Complete Examples
=================================

This page groups ``DataProtection`` examples by what you are protecting: strings, envelopes, files, and legacy-compatible payloads.

Protect an Application String
-----------------------------

Use this when you need easy encrypt/decrypt calls for short data stored in your app.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   $stringProtector = new StringProtector();
   $ciphertext = $stringProtector->encrypt('sensitive data', $key);
   $plaintext = $stringProtector->decrypt($ciphertext, $key);

Protect a Versioned Envelope
----------------------------

Use this when you want a structured protected payload that can be encoded and stored as one value.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   $envelopeProtector = new EnvelopeProtector();
   $envelope = $envelopeProtector->encrypt('payload', $key);
   $encodedEnvelope = $envelopeProtector->encodeEnvelope($envelope);
   $decoded = $envelopeProtector->decrypt($encodedEnvelope, $key);

Protect a File
--------------

Use this when you need stream-based encryption for files or large blobs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $fileKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $fileProtector = new FileProtector();
   $lastChunk = $fileProtector->encrypt('/tmp/in.bin', '/tmp/in.bin.epc', $fileKey, 8192, false);
   $fileProtector->decrypt('/tmp/in.bin.epc', '/tmp/in.dec.bin', $fileKey, 8192, false);

Work with Legacy OpenSSL-Compatible Payloads
--------------------------------------------

Use this when interoperability with an older OpenSSL-based payload format is required.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\OpenSSL\InteroperabilityCryptoHelper;

   $interop = new InteroperabilityCryptoHelper();
   $interopCipher = $interop->encryptString('legacy-payload', 'app-secret', 'salt-value', true);
   $interopPlain = $interop->decryptString($interopCipher, 'app-secret', 'salt-value', true);
