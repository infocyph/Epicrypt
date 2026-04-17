Crypto Complete Examples
========================

This page groups ``Crypto`` examples by primitive so you can choose the right building block for the data flow you are designing.

Encrypt a Message with AEAD
---------------------------

Use this when you want authenticated encryption for short application payloads.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $aeadKey = (new KeyMaterialGenerator())->generate(
       AeadAlgorithm::XCHACHA20_POLY1305_IETF->keyLength(),
   );

   $aead = new AeadCipher(AeadAlgorithm::XCHACHA20_POLY1305_IETF);
   $aeadCiphertext = $aead->encrypt('aead-message', $aeadKey, ['aad' => 'meta']);
   $aeadPlain = $aead->decrypt($aeadCiphertext, $aeadKey, ['aad' => 'meta']);

Encrypt with SecretBox
----------------------

Use this when you want sodium secretbox semantics with a shared symmetric key.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $secretBoxKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
   $secretBox = new SecretBoxCipher();
   $secretBoxCiphertext = $secretBox->encrypt('secretbox-message', $secretBoxKey);
   $secretBoxPlain = $secretBox->decrypt($secretBoxCiphertext, $secretBoxKey);

Encrypt to Another Party
------------------------

Use this when both parties have sodium box key pairs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;

   $sender = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: true);

   $publicBox = new PublicKeyBoxCipher();
   $publicBoxCiphertext = $publicBox->encrypt('public-box-message', [
       'recipient_public' => $recipient['public'],
       'sender_private' => $sender['private'],
   ]);
   $publicBoxPlain = $publicBox->decrypt($publicBoxCiphertext, [
       'sender_public' => $sender['public'],
       'recipient_private' => $recipient['private'],
   ]);

Seal a Message to One Recipient
-------------------------------

Use this when the sender does not need decrypt capability later.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\SealedBoxCipher;

   $keypair = sodium_crypto_box_keypair();
   $public = sodium_bin2base64(sodium_crypto_box_publickey($keypair), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $pair = sodium_bin2base64($keypair, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

   $sealed = new SealedBoxCipher();
   $sealedCiphertext = $sealed->encrypt('sealed-box-message', $public);
   $sealedPlain = $sealed->decrypt($sealedCiphertext, $pair);

Sign or MAC Data
----------------

Use signatures for asymmetric verification and MACs for shared-secret integrity.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\Mac;
   use Infocyph\Epicrypt\Crypto\Signature;

   $signKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $signatureService = new Signature();
   $signature = $signatureService->sign('sign-me', $signKeys['private']);
   $signatureValid = $signatureService->verify('sign-me', $signature, $signKeys['public']);

   $mac = new Mac();
   $macKey = $mac->generateKey();
   $tag = $mac->generate('mac-message', $macKey);
   $tagValid = $mac->verify('mac-message', $tag, $macKey);

Encrypt Large Files in Chunks
-----------------------------

Use this when a payload is too large for simple in-memory encryption.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
   use Infocyph\Epicrypt\Crypto\SecretStream;

   $streamKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $stream = new SecretStream($streamKey, StreamAlgorithm::XCHACHA20POLY1305, 'aad');
   $lastChunkSize = $stream->encrypt('/tmp/plain.bin', '/tmp/plain.bin.epc', 8192);
   $stream->decrypt('/tmp/plain.bin.epc', '/tmp/plain.dec.bin', 8192);

Encode Binary Safely
--------------------

Use this when you need a transport-friendly string representation for binary values.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\BinaryCodec;

   $codec = new BinaryCodec();
   $encoded = $codec->encode(random_bytes(32));
   $decoded = $codec->decode($encoded);
