Data Protection Domain
======================

Namespace: ``Infocyph\\Epicrypt\\DataProtection``

Scope
-----

Higher-level security workflows built on crypto primitives:

- string protection
- file protection
- envelope encryption
- key rotation and re-encryption helpers
- inspect/rotation decision helpers and key-ring-aware result objects

String Protector
----------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   $protector = StringProtector::forProfile();
   $ciphertext = $protector->encrypt('sensitive data', $key);
   $plaintext = $protector->decrypt($ciphertext, $key);
   $inspect = $protector->inspect($ciphertext);

String inspector fields:

- ``version``
- ``algorithm``
- ``keyId``

Key Rotation
------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $ring = new KeyRing(['previous' => $previousKey, 'current' => $currentKey], 'current');
   $result = StringProtector::forProfile()->decryptWithKeyRingResult($ciphertext, $ring);
   $plaintext = $result->plaintext;
   $matchedKeyId = $result->matchedKeyId;
   $usedFallbackKey = $result->usedFallbackKey;

   $stringProtector = StringProtector::forProfile();
   $needsRotation = $stringProtector->needsRotation($ciphertext, 'current');
   $needsReencrypt = $stringProtector->needsReencrypt($ciphertext, 'current');
   $rotatedCiphertext = $stringProtector->reencryptWithAnyKey($ciphertext, $ring, $currentKey);

Envelope Protector
------------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $masterKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
   $envelopeProtector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
   $envelope = $envelopeProtector->encrypt('payload', $masterKey);

   $encoded = $envelopeProtector->encodeEnvelope($envelope);
   $plain = $envelopeProtector->decrypt($encoded, $masterKey);

Envelope payload includes:

- ``v`` format version
- ``alg`` algorithm marker
- ``dek_alg`` data-encryption-key algorithm marker
- ``created_at`` unix timestamp
- optional ``kid`` and ``purpose``
- ``encrypted_data``
- ``encrypted_key``

Envelope Re-Encryption
----------------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Security\KeyRing;

   $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
   $ring = new KeyRing(['previous' => $previousMasterKey, 'current' => $currentMasterKey], 'current');
   $result = $protector->decryptWithKeyRingResult($encoded, $ring);
   $inspect = $protector->inspect($encoded);
   $needsRotation = $protector->needsRotation($encoded, 'current');
   $needsReencrypt = $protector->needsReencrypt($encoded, 'current', 86400);
   $rotatedEnvelope = $protector->reencryptWithAnyKey($encoded, $ring, $currentMasterKey);
   $plain = $protector->decrypt($rotatedEnvelope, $currentMasterKey);

File Re-Encryption
------------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $ring = new KeyRing(['previous' => $previousFileKey, 'current' => $currentFileKey], 'current');
   $result = FileProtector::forProfile(SecurityProfile::MODERN)->reencryptWithAnyKey(
       '/tmp/input.txt.epc',
       '/tmp/input.txt.new.epc',
       $ring,
       $currentFileKey,
   );

In-place rotation with backup/rollback:

.. code-block:: php

   $result = FileProtector::forProfile(SecurityProfile::MODERN)->reencryptInPlaceWithAnyKey(
       '/tmp/input.txt.epc',
       $ring,
       $currentFileKey,
   );

File Protector
--------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $key = (new KeyMaterialGenerator())
       ->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);

   $file = FileProtector::forProfile(SecurityProfile::MODERN);
   $bytesWritten = $file->encrypt('/tmp/input.txt', '/tmp/input.txt.epc', $key);
   $file->decrypt('/tmp/input.txt.epc', '/tmp/input.dec.txt', $key);

Protection AAD
--------------

Use ``ProtectionAad`` to build deterministic additional-authenticated-data namespaces.

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\ProtectionAad;

   $stringAad = ProtectionAad::forString('user.email', 'v1');
   $fileAad = ProtectionAad::forFile('backup.archive', 'v1');
   $envelopeAad = ProtectionAad::forEnvelope('merchant.secret', 'v1');
