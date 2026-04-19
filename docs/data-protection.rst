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

Key Rotation
------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Security\KeyRing;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $ring = new KeyRing(['previous' => $previousKey, 'current' => $currentKey], 'current');
   $result = StringProtector::forProfile()->decryptWithAnyKeyResult($ciphertext, $ring);
   $plaintext = $result->plaintext;
   $rotatedCiphertext = StringProtector::forProfile()->reencryptWithAnyKey($ciphertext, $ring, $currentKey);

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
- ``encrypted_data``
- ``encrypted_key``

Envelope Re-Encryption
----------------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Security\KeyRing;

   $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
   $ring = new KeyRing(['previous' => $previousMasterKey, 'current' => $currentMasterKey], 'current');
   $result = $protector->decryptWithAnyKeyResult($encoded, $ring);
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

File Protector
--------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $key = (new KeyMaterialGenerator())
       ->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);

   $file = FileProtector::forProfile(SecurityProfile::MODERN);
   $file->encrypt('/tmp/input.txt', '/tmp/input.txt.epc', $key);
   $file->decrypt('/tmp/input.txt.epc', '/tmp/input.dec.txt', $key);
