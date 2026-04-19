Crypto Domain
=============

Namespace: ``Infocyph\\Epicrypt\\Crypto``

Scope
-----

Direct cryptographic primitives and operations:

- AEAD
- secret-box
- public-key box
- sealed-box
- detached signature
- MAC
- stream encryption
- binary codec

This is the lower-level surface of Epicrypt.

For most new applications, prefer the higher-level ``Password``, ``Token``, ``DataProtection``, and ``Security`` domains first, then drop down into ``Crypto`` only when you truly need primitive-level control.

AEAD Cipher
-----------

.. code-block:: php

   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())
       ->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

   $cipher = new AeadCipher(AeadAlgorithm::XCHACHA20_POLY1305_IETF);
   $encrypted = $cipher->encrypt('message', $key, ['aad' => 'ctx']);
   $plain = $cipher->decrypt($encrypted, $key, ['aad' => 'ctx']);

Supported AEAD algorithms:

- ``aes-256-gcm``
- ``chacha20-poly1305``
- ``chacha20-poly1305-ietf``
- ``xchacha20-poly1305-ietf``

SecretBox Cipher
----------------

.. code-block:: php

   use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
   $cipher = new SecretBoxCipher();

   $encrypted = $cipher->encrypt('message', $key);
   $plain = $cipher->decrypt($encrypted, $key);

PublicKeyBox Cipher
-------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;

   $sender = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: true);

   $cipher = new PublicKeyBoxCipher();
   $encrypted = $cipher->encrypt('message', [
       'recipient_public' => $recipient['public'],
       'sender_private' => $sender['private'],
   ]);

   $plain = $cipher->decrypt($encrypted, [
       'sender_public' => $sender['public'],
       'recipient_private' => $recipient['private'],
   ]);

SealedBox Cipher
----------------

.. code-block:: php

   use Infocyph\Epicrypt\Crypto\SealedBoxCipher;

   $keypair = sodium_crypto_box_keypair();
   $public = sodium_bin2base64(sodium_crypto_box_publickey($keypair), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $pair = sodium_bin2base64($keypair, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

   $cipher = new SealedBoxCipher();
   $encrypted = $cipher->encrypt('message', $public);
   $plain = $cipher->decrypt($encrypted, $pair);

MAC and Signature
-----------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\Mac;
   use Infocyph\Epicrypt\Crypto\Signature;

   $mac = new Mac();
   $macKey = $mac->generateKey();
   $tag = $mac->generate('message', $macKey);
   $isMacValid = $mac->verify('message', $tag, $macKey);

   $keys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $sig = new Signature();
   $detached = $sig->sign('message', $keys['private']);
   $isSigValid = $sig->verify('message', $detached, $keys['public']);

SecretStream (File Streaming)
-----------------------------

``SecretStream`` is optimized for chunked file encryption/decryption and powers ``DataProtection\\FileProtector``.

- default algorithm: ``xchacha20poly1305``
- alternate: ``xchacha20``

Binary Codec
------------

``BinaryCodec`` wraps Base64URL encode/decode helpers.
