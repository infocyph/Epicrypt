Certificates and key exchange
=============================

Use this domain for OpenSSL certificates, RSA/EC key pairs, Sodium box and
signing key pairs, PKCS#12 bundles, and authenticated peer key agreement.
OpenSSL RSA generation defaults to 3072 bits; EC generation defaults to
``prime256v1``. RSA-1024 is not supported.

Complete path: create a CA, issue a leaf, and validate deployment
-----------------------------------------------------------------

This self-contained workflow creates a private CA, accepts a service CSR,
issues a constrained leaf certificate, and performs the checks needed before
deployment. In production, generate and operate the CA in dedicated protected
infrastructure rather than in the application process.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateChainVerifier;
   use Infocyph\Epicrypt\Certificate\CertificateExpiry;
   use Infocyph\Epicrypt\Certificate\CertificateFingerprint;
   use Infocyph\Epicrypt\Certificate\CertificateKeyMatcher;
   use Infocyph\Epicrypt\Certificate\CertificateOptions;
   use Infocyph\Epicrypt\Certificate\Enum\CertificateDigest;
   use Infocyph\Epicrypt\Certificate\Enum\CertificatePurpose;
   use Infocyph\Epicrypt\Certificate\Enum\ExtendedKeyUsage;
   use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateAuthority;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CsrBuilder;

   $caKeys = KeyPairGenerator::rsa()->generate($caPrivateKeyPassphrase);
   $caOptions = new CertificateOptions(
       days: 3650,
       keyUsage: [KeyUsage::KEY_CERT_SIGN, KeyUsage::CRL_SIGN],
       isCa: true,
   );
   $caCertificate = new CertificateBuilder()->selfSign(
       ['commonName' => 'Example Internal Root CA', 'organizationName' => 'Example Inc.'],
       $caKeys['private'],
       passphrase: $caPrivateKeyPassphrase,
       options: $caOptions,
   );

   $serviceKeys = KeyPairGenerator::rsa()->generate($serviceKeyPassphrase);
   $leafOptions = new CertificateOptions(
       days: 90,
       sanDns: ['orders.internal.example'],
       keyUsage: [KeyUsage::DIGITAL_SIGNATURE, KeyUsage::KEY_ENCIPHERMENT],
       extendedKeyUsage: [ExtendedKeyUsage::SERVER_AUTH],
   );
   $csr = new CsrBuilder()->build(
       ['commonName' => 'orders.internal.example', 'organizationName' => 'Example Inc.'],
       $serviceKeys['private'],
       $serviceKeyPassphrase,
       $leafOptions,
   );
   $serviceCertificate = new CertificateAuthority()->signCsr(
       $csr,
       $caCertificate,
       $caKeys['private'],
       $leafOptions,
       $caPrivateKeyPassphrase,
   );

   $chainValid = new CertificateChainVerifier()->verify(
       $serviceCertificate,
       [$caCertificate],
       CertificatePurpose::SSL_SERVER,
   );
   $keyMatches = new CertificateKeyMatcher()->privateKeyMatches(
       $serviceCertificate,
       $serviceKeys['private'],
       $serviceKeyPassphrase,
   );
   $expiresTooSoon = new CertificateExpiry()->isExpired(
       $serviceCertificate,
       leewaySeconds: 14 * 86400,
   );
   if (!$chainValid || !$keyMatches || $expiresTooSoon) {
       throw new RuntimeException('Certificate deployment validation failed.');
   }

   $deploymentFingerprint = new CertificateFingerprint()->fingerprint(
       $serviceCertificate,
       CertificateDigest::SHA256,
   );

Deploy the leaf certificate, encrypted leaf private key, and required chain;
publish or pin the SHA-256 fingerprint through a trusted channel. Never deploy
the CA private key with the service.

Chain-purpose validation does not perform RFC 6125 hostname matching. At the
TLS boundary, also verify the requested DNS name or IP address with the HTTP,
TLS, or socket client that owns the connection. A valid server-purpose chain
must never be treated as proof that the leaf identifies an arbitrary hostname.

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

   $keys = KeyPairGenerator::rsa()->generate('private-key-passphrase');
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

   $leafKeys = KeyPairGenerator::rsa()->generate();
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
key pairs. Normal Sodium methods consume Base64URL keys; normal OpenSSL methods
consume PEM keys. ``deriveKey()`` returns Base64URL and ``deriveBinaryKey()``
returns raw bytes. Use the explicitly named ``*FromBinaryKeys()`` variants only
when the caller owns raw Sodium keys or PKCS#8 private/SPKI public DER OpenSSL
keys. No public method
returns the backend's raw Diffie-Hellman secret.

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

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $alice = KeyPairGenerator::ec(OpenSslCurveName::PRIME256V1)->generate();
   $bob = KeyPairGenerator::ec(OpenSslCurveName::PRIME256V1)->generate();
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
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $rsa4096 = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_4096)->generate();
   $p384 = KeyPairGenerator::ec(OpenSslCurveName::SECP384R1)->generate();
