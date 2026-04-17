Crypto Complete Examples
========================

This page contains complete usage examples for ``Crypto`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Crypto\BinaryCodec;
   use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
   use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
   use Infocyph\Epicrypt\Crypto\Mac;
   use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;
   use Infocyph\Epicrypt\Crypto\SealedBoxCipher;
   use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
   use Infocyph\Epicrypt\Crypto\SecretStream;
   use Infocyph\Epicrypt\Crypto\Signature;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   // AeadCipher with context options: aad, key_is_binary, nonce, nonce_is_binary
   $aeadKey = (new KeyMaterialGenerator())->generate(
       AeadAlgorithm::XCHACHA20_POLY1305_IETF->keyLength(),
   );
   $aead = new AeadCipher(AeadAlgorithm::XCHACHA20_POLY1305_IETF);
   $aeadCiphertext = $aead->encrypt('aead-message', $aeadKey, ['aad' => 'meta']);
   $aeadPlain = $aead->decrypt($aeadCiphertext, $aeadKey, ['aad' => 'meta']);

   // SecretBoxCipher (context option: key_is_binary)
   $secretBoxKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
   $secretBox = new SecretBoxCipher();
   $secretBoxCiphertext = $secretBox->encrypt('secretbox-message', $secretBoxKey);
   $secretBoxPlain = $secretBox->decrypt($secretBoxCiphertext, $secretBoxKey);

   // PublicKeyBoxCipher (keys are arrays + optional key_is_binary context)
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

   // SealedBoxCipher
   $keypair = sodium_crypto_box_keypair();
   $public = sodium_bin2base64(sodium_crypto_box_publickey($keypair), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $pair = sodium_bin2base64($keypair, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $sealed = new SealedBoxCipher();
   $sealedCiphertext = $sealed->encrypt('sealed-box-message', $public);
   $sealedPlain = $sealed->decrypt($sealedCiphertext, $pair);

   // Signature (context option: key_is_binary)
   $signKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $signatureService = new Signature();
   $signature = $signatureService->sign('sign-me', $signKeys['private']);
   $signatureValid = $signatureService->verify('sign-me', $signature, $signKeys['public']);

   // MAC (context option: key_is_binary)
   $mac = new Mac();
   $macKey = $mac->generateKey();
   $tag = $mac->generate('mac-message', $macKey);
   $tagValid = $mac->verify('mac-message', $tag, $macKey);

   // SecretStream for chunked file encryption/decryption
   $streamKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $stream = new SecretStream($streamKey, StreamAlgorithm::XCHACHA20POLY1305, 'aad');
   $lastChunkSize = $stream->encrypt('/tmp/plain.bin', '/tmp/plain.bin.epc', 8192);
   $stream->decrypt('/tmp/plain.bin.epc', '/tmp/plain.dec.bin', 8192);

   // BinaryCodec
   $codec = new BinaryCodec();
   $encoded = $codec->encode(random_bytes(32));
   $decoded = $codec->decode($encoded);
