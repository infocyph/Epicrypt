Data Protection Complete Examples
=================================

This page contains complete usage examples for ``Data Protection`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\DataProtection\OpenSSL\InteroperabilityCryptoHelper;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   // StringProtector
   $stringProtector = new StringProtector();
   $ciphertext = $stringProtector->encrypt('sensitive data', $key);
   $plaintext = $stringProtector->decrypt($ciphertext, $key);

   // EnvelopeProtector
   $envelopeProtector = new EnvelopeProtector();
   $envelope = $envelopeProtector->encrypt('payload', $key);
   $encodedEnvelope = $envelopeProtector->encodeEnvelope($envelope);
   $decoded = $envelopeProtector->decrypt($encodedEnvelope, $key);

   // FileProtector
   $fileKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $fileProtector = new FileProtector();
   $lastChunk = $fileProtector->encrypt('/tmp/in.bin', '/tmp/in.bin.epc', $fileKey, 8192, false);
   $fileProtector->decrypt('/tmp/in.bin.epc', '/tmp/in.dec.bin', $fileKey, 8192, false);

   // OpenSSL interoperability helper
   $interop = new InteroperabilityCryptoHelper();
   $interopCipher = $interop->encryptString('legacy-payload', 'app-secret', 'salt-value', true);
   $interopPlain = $interop->decryptString($interopCipher, 'app-secret', 'salt-value', true);
