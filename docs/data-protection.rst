Data Protection Domain
======================

Namespace: ``Infocyph\\Epicrypt\\DataProtection``

Scope
-----

Higher-level security workflows built on crypto primitives:

- string protection
- file protection
- envelope encryption
- OpenSSL interoperability helper
- migration and re-encryption helpers

String Protector
----------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   $protector = new StringProtector();
   $ciphertext = $protector->encrypt('sensitive data', $key);
   $plaintext = $protector->decrypt($ciphertext, $key);

Rotation and Migration
----------------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Security\KeyRing;

   $ring = new KeyRing(['legacy' => $legacyKey, 'current' => $currentKey], 'current');
   $plaintext = (new StringProtector())->decryptWithAny($ciphertext, $ring);
   $migrated = (new StringProtector())->reencryptWithAny($ciphertext, $ring, $currentKey);

Envelope Protector
------------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $masterKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
   $envelope = (new EnvelopeProtector())->encrypt('payload', $masterKey);

   $encoded = (new EnvelopeProtector())->encodeEnvelope($envelope);
   $plain = (new EnvelopeProtector())->decrypt($encoded, $masterKey);

Envelope payload includes:

- ``v`` format version
- ``alg`` algorithm marker
- ``encrypted_data``
- ``encrypted_key``

Envelope Re-Encryption
----------------------

.. code-block:: php

   $migrated = (new EnvelopeProtector())->reencryptWithAny($encoded, [$legacyMasterKey], $currentMasterKey);
   $plain = (new EnvelopeProtector())->decrypt($migrated, $currentMasterKey);

File Protector
--------------

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())
       ->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);

   $file = new FileProtector();
   $file->encrypt('/tmp/input.txt', '/tmp/input.txt.epc', $key);
   $file->decrypt('/tmp/input.txt.epc', '/tmp/input.dec.txt', $key);

OpenSSL Interoperability Helper
-------------------------------

``DataProtection\\OpenSSL\\InteroperabilityCryptoHelper`` provides a compatibility-oriented string encryption format using OpenSSL + HMAC.

Prefer it only for compatibility or migration boundaries, not for new storage formats.
