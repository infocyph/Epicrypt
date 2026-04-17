Certificate Complete Examples
=============================

This page groups the main ``Certificate`` APIs by job so you can learn them as a sequence instead of reading one long example block.

Generate Key Pairs
------------------

Use this when you need OpenSSL or sodium key material for encryption, signatures, or interop.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\KeyPairType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   // RSA keys for general PEM-based interoperability.
   $rsaKeys = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048, OpenSslKeyType::RSA)->generate();

   // EC keys for OpenSSL elliptic-curve workflows.
   $ecKeys = KeyPairGenerator::openSsl(
       bits: OpenSslRsaBits::BITS_2048,
       type: OpenSslKeyType::EC,
       curveName: OpenSslCurveName::PRIME256V1,
   )->generate();

   // Sodium key pairs for box-based encryption.
   $sodiumBoxKeys = KeyPairGenerator::sodium()->generate(asBase64Url: true);

   // Sodium signing key pairs.
   $sodiumSignKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);

   // Select a generator from a higher-level enum when the type is dynamic.
   $autoTypeKeys = KeyPairGenerator::forType(KeyPairType::OPENSSL_RSA)->generate();

Build a CSR and Certificate
---------------------------

Use this when a service needs a CSR for a CA or a self-signed certificate for local/internal environments.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateParser;
   use Infocyph\Epicrypt\Certificate\CsrBuilder;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $rsaKeys = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048, OpenSslKeyType::RSA)->generate();
   $dn = [
       'countryName' => 'US',
       'organizationName' => 'Epicrypt',
       'commonName' => 'epicrypt.local',
   ];

   $csr = CsrBuilder::openSsl()->build($dn, $rsaKeys['private']);
   $cert = CertificateBuilder::openSsl('sha512')->selfSign($dn, $rsaKeys['private'], 365);
   $parsed = CertificateParser::openSsl()->parse($cert);

Derive Shared Secrets
---------------------

Use this when two parties exchange public keys and need a shared secret for later encryption.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $localKeys = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $peerKeys = KeyPairGenerator::sodium()->generate(asBase64Url: true);

   $exchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
   $secretAB = $exchange->derive($localKeys['private'], $peerKeys['public']);
   $activeBackend = $exchange->backend(); // enum KeyExchangeBackend

   // Named constructors are useful when the backend is fixed.
   $openSslExchange = KeyExchange::openSsl();
   $sodiumExchange = KeyExchange::sodium();

Use Backend-Specific APIs
-------------------------

Use these only when you need direct access to backend-specific behavior.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\DiffieHellman;
   use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;
   use Infocyph\Epicrypt\Certificate\Sodium\SessionKeyExchange;
   use Infocyph\Epicrypt\Certificate\Sodium\SigningKeyPairGenerator;

   $rsaKeys = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048, OpenSslKeyType::RSA)->generate();
   $sodiumDirect = new SessionKeyExchange();
   $opensslDirect = new DiffieHellman();
   $directSignKeys = (new SigningKeyPairGenerator())->generate(asBase64Url: true);

   // OpenSSL RSA encryption for interoperability with PEM-based systems.
   $rsaCipher = new RsaCipher();
   $encrypted = $rsaCipher->encrypt('interop-message', $rsaKeys['public']);
   $decrypted = $rsaCipher->decrypt($encrypted, $rsaKeys['private']);
