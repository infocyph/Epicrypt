Cryptographic primitives
========================

Use this lower-level domain when a higher-level ``DataProtection``, ``Token``,
``Password``, or ``Security`` capability does not fit the protocol.

Complete path: sign and encrypt a service message
-------------------------------------------------

The sender signs the exact payload with its Ed25519 key, then anonymously seals
the signed envelope to the recipient's X25519 box key. The recipient decrypts
first and accepts the message only after verifying the signature with a pinned
sender public key.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\SealedBoxCipher;
   use Infocyph\Epicrypt\Crypto\Signature;

   $senderSigningKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $recipientKeyPair = sodium_crypto_box_keypair();
   $recipientPublicKey = sodium_bin2base64(
       sodium_crypto_box_publickey($recipientKeyPair),
       SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
   );
   $encodedRecipientKeyPair = sodium_bin2base64(
       $recipientKeyPair,
       SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
   );

   $payload = json_encode([
       'message_id' => 'msg-1847',
       'operation' => 'release-order',
       'order_id' => 'order-42',
   ], JSON_THROW_ON_ERROR);
   $signatures = new Signature();
   $signature = $signatures->sign($payload, $senderSigningKeys['private']);
   $envelope = json_encode([
       'payload' => $payload,
       'signature' => $signature,
   ], JSON_THROW_ON_ERROR);
   $ciphertext = new SealedBoxCipher()->encrypt($envelope, $recipientPublicKey);

   $opened = new SealedBoxCipher()->decrypt($ciphertext, $encodedRecipientKeyPair);
   $decoded = json_decode($opened, true, flags: JSON_THROW_ON_ERROR);
   if (!is_string($decoded['payload'] ?? null)
       || !is_string($decoded['signature'] ?? null)
       || !$signatures->verify(
           $decoded['payload'],
           $decoded['signature'],
           $senderSigningKeys['public'],
       )) {
       throw new RuntimeException('Encrypted service message rejected.');
   }

   $trustedMessage = json_decode($decoded['payload'], true, flags: JSON_THROW_ON_ERROR);

Provision the recipient private key and pinned sender public key independently.
A sealed box hides the message from everyone except the recipient; the detached
signature supplies sender authentication and auditability.

AEAD
----

``AeadCipher`` defaults to XChaCha20-Poly1305. The approved explicit choices
are AES-256-GCM, ChaCha20-Poly1305, ChaCha20-Poly1305-IETF,
XChaCha20-Poly1305-IETF, AEGIS-128L, and AEGIS-256. AES-256-GCM additionally
requires platform hardware support. AEGIS requires libsodium 1.0.19 or newer;
an unavailable explicit selection fails without downgrade.

This recipe encrypts a payment-provider credential and binds the ciphertext to
the immutable merchant record and schema version.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = new KeyMaterialGenerator()->forAead();
   $aad = 'merchant=1847;field=provider-token;schema=1';
   $cipher = new AeadCipher(); // XChaCha20-Poly1305

   $storedCiphertext = $cipher->encrypt($providerToken, $key, $aad, keyId: 'merchant-2026-08');
   $restoredToken = $cipher->decrypt($storedCiphertext, $key, $aad);

Explicit selection is reserved for protocol interoperability:

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;

   $aes = new AeadCipher(AeadAlgorithm::AES_256_GCM);

Runtime-gated AEGIS selection is explicit:

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;

   $algorithm = AeadAlgorithm::AEGIS_256;
   if (!$algorithm->isAvailable()) {
       throw new RuntimeException('This deployment does not provide AEGIS-256.');
   }
   $key = random_bytes($algorithm->keyLength());
   $cipher = new AeadCipher($algorithm);
   $payload = $cipher->encryptWithBinaryKey($record, $key, 'telemetry-record/v1');
   $record = $cipher->decryptWithBinaryKey($payload, $key, 'telemetry-record/v1');

Shared-key and public-key boxes
-------------------------------

Use ``SecretBoxCipher`` for a shared-key Sodium secret-box protocol,
``PublicKeyBoxCipher`` when sender and recipient identities are both known, and
``SealedBoxCipher`` when an anonymous sender only has the recipient public key.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;

   $dispatch = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $warehouse = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $box = new PublicKeyBoxCipher();

   $message = $box->encrypt(
       $shippingInstruction,
       $warehouse['public'],
       $dispatch['private'],
   );
   $instruction = $box->decrypt(
       $message,
       $dispatch['public'],
       $warehouse['private'],
   );

``SecretBoxCipher`` and ``SealedBoxCipher`` expose the same explicit
``encrypt()``/``decrypt()`` shape for their respective key material.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\SealedBoxCipher;
   use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $sharedKey = new KeyMaterialGenerator()->forSecretBox();
   $secretBox = new SecretBoxCipher();
   $stored = $secretBox->encrypt('shared deployment secret', $sharedKey);
   $restored = $secretBox->decrypt($stored, $sharedKey);

   $recipientPair = sodium_crypto_box_keypair();
   $recipientPublic = sodium_bin2base64(
       sodium_crypto_box_publickey($recipientPair),
       SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
   );
   $encodedPair = sodium_bin2base64($recipientPair, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $sealedBox = new SealedBoxCipher();
   $sealed = $sealedBox->encrypt('anonymous incident report', $recipientPublic);
   $report = $sealedBox->decrypt($sealed, $encodedPair);

Detached signatures and MACs
-----------------------------

Use a detached signature when verifiers must not possess signing authority.
Use a MAC when both parties are trusted to share the same secret.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\Mac;
   use Infocyph\Epicrypt\Crypto\Signature;

   $manifest = '{"release":"2026.08","sha512":"..."}';
   $releaseKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $signature = new Signature()->sign($manifest, $releaseKeys['private']);
   $trusted = new Signature()->verify($manifest, $signature, $releaseKeys['public']);

   $mac = new Mac();
   $webhookKey = $mac->generateKey();
   $tag = $mac->generate($manifest, $webhookKey);
   $authenticated = $mac->verify($manifest, $tag, $webhookKey);

Authenticated file streaming
----------------------------

``SecretStream`` is the specialized XChaCha20-Poly1305 primitive behind
``DataProtection\FileProtector``. Prefer ``FileProtector`` for application
files because it also authenticates purpose, AAD, key ID, and framing metadata.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\SecretStream;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $binaryKey = new KeyMaterialGenerator()->forSecretStream(asBase64Url: false);
   $stream = new SecretStream($binaryKey, additionalData: 'video-export/v1');
   $stream->encrypt('/exports/video.mp4', '/exports/video.mp4.encrypted');
   $stream->decrypt('/exports/video.mp4.encrypted', '/restore/video.mp4');

Chunk sizes are limited to 1 byte through 16 MiB; the default is 64 KiB.
Destinations are staged and committed only after complete success.

Binary encoding
---------------

``BinaryCodec`` provides explicit Base64URL encoding and decoding for protocol
boundaries. Do not confuse encoded text with raw binary key material; methods
whose names include ``BinaryKey`` intentionally require raw bytes.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\BinaryCodec;

   $codec = new BinaryCodec();
   $transportValue = $codec->encode($binaryProtocolValue);
   $binaryProtocolValue = $codec->decode($transportValue);
