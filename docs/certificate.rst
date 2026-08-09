Certificates and key exchange
=============================

Use this domain for OpenSSL certificates, RSA/EC key pairs, Sodium box and
signing key pairs, PKCS#12 bundles, and authenticated peer key agreement.
OpenSSL RSA generation defaults to 3072 bits; EC generation defaults to
``prime256v1``. RSA-1024 is not supported.

Issue a short-lived service certificate
----------------------------------------

This is useful for an internal TLS service or a development certificate. A
production CA normally signs a CSR instead of self-signing the leaf.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateKeyMatcher;
   use Infocyph\Epicrypt\Certificate\CertificateOptions;
   use Infocyph\Epicrypt\Certificate\Enum\ExtendedKeyUsage;
   use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;

   $keys = KeyPairGenerator::openSsl()->generate('private-key-passphrase');
   $options = new CertificateOptions(
       days: 90,
       sanDns: ['api.internal.example'],
       keyUsage: [KeyUsage::DIGITAL_SIGNATURE, KeyUsage::KEY_ENCIPHERMENT],
       extendedKeyUsage: [ExtendedKeyUsage::SERVER_AUTH],
   );

   $certificate = new CertificateBuilder()->selfSign(
       ['commonName' => 'api.internal.example', 'organizationName' => 'Example Inc.'],
       $keys['private'],
       passphrase: 'private-key-passphrase',
       options: $options,
   );

   $matches = new CertificateKeyMatcher()->privateKeyMatches(
       $certificate,
       $keys['private'],
       'private-key-passphrase',
   );

CA issuance follows the same model: create a CSR with ``CsrBuilder`` and sign it
with ``CertificateAuthority``. Use ``CertificateChainVerifier``,
``CertificateExpiry``, and ``CertificateFingerprint`` for deployment checks;
use ``Pkcs12`` only where a consumer requires a PFX/P12 bundle.

Create and inspect a CA-signed certificate
------------------------------------------

The CA certificate and private key below are assumed to come from protected CA
storage. The leaf service produces the CSR; the CA signs it under an explicit
leaf policy.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateExpiry;
   use Infocyph\Epicrypt\Certificate\CertificateFingerprint;
   use Infocyph\Epicrypt\Certificate\CertificateOptions;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateAuthority;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateParser;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CsrBuilder;

   $leafKeys = KeyPairGenerator::openSsl()->generate();
   $options = new CertificateOptions(days: 90, sanDns: ['worker.internal.example']);
   $csr = new CsrBuilder()->build(
       ['commonName' => 'worker.internal.example'],
       $leafKeys['private'],
       options: $options,
   );
   $leafCertificate = new CertificateAuthority()->signCsr(
       $csr,
       $caCertificatePem,
       $caPrivateKeyPem,
       $options,
       passphrase: $caPrivateKeyPassphrase,
   );

   $metadata = new CertificateParser()->parse($leafCertificate);
   $fingerprint = new CertificateFingerprint()->fingerprint($leafCertificate);
   $renewNow = new CertificateExpiry()->isExpired($leafCertificate, leewaySeconds: 14 * 86400);

Use ``CertificateChainVerifier`` against the intended trust anchors before
trusting a peer certificate. ``PemNormalizer`` normalizes line endings and a
single trailing newline; it does not validate trust.

Derive a service-to-service session key
---------------------------------------

This Diffie-Hellman-style exchange lets two services derive the same session
key without transmitting it. The peer public keys must still be authenticated
by certificates, signatures, or trusted pinning; key agreement alone does not
prove who the peer is.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Generate\SaltGenerator;

   // Each service creates and retains its own private key. Only public keys and
   // this non-secret salt cross the authenticated channel.
   $alice = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $bob = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $salt = new SaltGenerator()->generate(32, asBase64Url: false);
   $context = 'billing-api/session-encryption/v1';

   $aliceSessionKey = KeyExchange::sodium()->deriveKey(
       $alice['private'],
       $bob['public'],
       32,
       $context,
       $salt,
   );
   $bobSessionKey = KeyExchange::sodium()->deriveKey(
       $bob['private'],
       $alice['public'],
       32,
       $context,
       $salt,
   );

   if (!hash_equals($aliceSessionKey, $bobSessionKey)) {
       throw new RuntimeException('The authenticated key exchange failed.');
   }

``KeyExchange`` feeds the raw agreement secret through SHA-512 HKDF and erases
the raw secret. Always use a non-empty, versioned, application-specific
context. ``KeyExchange::openSsl()`` supports the same workflow with OpenSSL EC
key pairs.

Directional Sodium ``crypto_kx`` session keys
----------------------------------------------

For a new client/server protocol, prefer ``crypto_kx``. Explicit roles produce
different receive and transmit keys.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Sodium\SessionKeyExchange;

   $exchange = new SessionKeyExchange();
   $clientKeyPair = $exchange->generateKeyPair();
   $serverKeyPair = $exchange->generateKeyPair();
   $clientPublic = sodium_crypto_kx_publickey($clientKeyPair);
   $serverPublic = sodium_crypto_kx_publickey($serverKeyPair);

   // Authenticate the public keys before accepting this session.
   $client = $exchange->clientSessionKeys($clientKeyPair, $serverPublic);
   $server = $exchange->serverSessionKeys($serverKeyPair, $clientPublic);
   if (!hash_equals($client->transmitKey, $server->receiveKey)
       || !hash_equals($server->transmitKey, $client->receiveKey)) {
       throw new RuntimeException('Directional session setup failed.');
   }

Never log the keypairs or directional keys. Raw X25519 through
``KeyExchange::sodium()`` remains available for protocols requiring a
caller-defined transcript salt and versioned HKDF context.

OpenSSL ECDH with context-bound HKDF
------------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $alice = KeyPairGenerator::openSsl(type: OpenSslKeyType::EC)->generate();
   $bob = KeyPairGenerator::openSsl(type: OpenSslKeyType::EC)->generate();
   $transcriptSalt = random_bytes(32);
   $aliceKey = KeyExchange::openSsl()->deriveBinaryKey(
       $alice['private'], $bob['public'], 32, 'orders-service/channel/v1', $transcriptSalt,
   );
   $bobKey = KeyExchange::openSsl()->deriveBinaryKey(
       $bob['private'], $alice['public'], 32, 'orders-service/channel/v1', $transcriptSalt,
   );

The raw ``openssl_pkey_derive()`` result is never returned as an application
key. Authenticate the peer key and bind the transcript before using the result.

Advanced Ristretto255 protocol primitives
-----------------------------------------

``Ristretto255`` is for reviewed protocol construction, not a drop-in key
exchange or session protocol.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\Ristretto255;

   $group = new Ristretto255();
   $secretScalar = $group->randomScalar();
   $publicElement = $group->multiplyBase($secretScalar);
   if (!$group->isValidPoint($publicElement)) {
       throw new RuntimeException('Invalid Ristretto element.');
   }

Use only a specification with domain separation, transcript binding, official
vectors, and expert review. Never use a raw group element as an encryption key.

Supported key-pair choices are RSA (3072 bits by default, with approved 2048,
3072, 4096, and 8192-bit selections), OpenSSL EC (``prime256v1`` by default, plus
``secp384r1`` and ``secp521r1``), Sodium box keys, and Sodium signing keys.

Select a non-default size or curve only when the consuming protocol requires
it:

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $rsa4096 = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_4096)->generate();
   $p384 = KeyPairGenerator::openSsl(
       type: OpenSslKeyType::EC,
       curveName: OpenSslCurveName::SECP384R1,
   )->generate();
