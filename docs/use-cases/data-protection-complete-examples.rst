Data Protection Complete Examples
=================================

This page groups ``DataProtection`` examples by what you are protecting: strings, envelopes, and files.

Protect an Application String
-----------------------------

Use this when you need easy encrypt/decrypt calls for short data stored in your app.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   $stringProtector = StringProtector::forProfile();
   $ciphertext = $stringProtector->encrypt('sensitive data', $key);
   $plaintext = $stringProtector->decrypt($ciphertext, $key);
   $inspect = $stringProtector->inspect($ciphertext);
   $needsRotation = $stringProtector->needsRotation($ciphertext, 'current-key-id');

Protect a Versioned Envelope
----------------------------

Use this when you want a structured protected payload that can be encoded and stored as one value.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   $envelopeProtector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
   $envelope = $envelopeProtector->encrypt('payload', $key);
   $encodedEnvelope = $envelopeProtector->encodeEnvelope($envelope);
   $decoded = $envelopeProtector->decrypt($encodedEnvelope, $key);
   $envelopeInspect = $envelopeProtector->inspect($encodedEnvelope);

Protect a File
--------------

Use this when you need stream-based encryption for files or large blobs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $fileKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $fileProtector = FileProtector::forProfile(SecurityProfile::MODERN);
   $bytesWritten = $fileProtector->encrypt('/tmp/in.bin', '/tmp/in.bin.epc', $fileKey, 8192, false);
   $fileProtector->decrypt('/tmp/in.bin.epc', '/tmp/in.dec.bin', $fileKey, 8192, false);

Use Key Rings and AAD
---------------------

Use this when active/fallback key flows and explicit domain-separated AAD are required.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionAad;
   use Infocyph\Epicrypt\Security\KeyRing;

   $ring = new KeyRing([
       'k-old' => 'previous-key',
       'k-current' => 'active-key',
   ], 'k-current');

   $aad = ProtectionAad::forString('user.email', 'v1');
   $sealed = $stringProtector->encryptWithKeyRing('alice@example.com', $ring, ['aad' => $aad]);
   $openResult = $stringProtector->decryptWithKeyRingResult($sealed, $ring, ['aad' => $aad]);

   $rotatedInPlace = $fileProtector->reencryptInPlaceWithAnyKey('/tmp/in.bin.epc', $ring, $fileKey);
