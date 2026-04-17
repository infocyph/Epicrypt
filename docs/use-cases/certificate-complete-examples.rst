Certificate Complete Examples
=============================

This page contains complete usage examples for ``Certificate`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateParser;
   use Infocyph\Epicrypt\Certificate\CsrBuilder;
   use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
   use Infocyph\Epicrypt\Certificate\Enum\KeyPairType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;
   use Infocyph\Epicrypt\Certificate\OpenSSL\DiffieHellman;
   use Infocyph\Epicrypt\Certificate\Sodium\SessionKeyExchange;
   use Infocyph\Epicrypt\Certificate\Sodium\SigningKeyPairGenerator;

   // KeyPairGenerator
   $rsaKeys = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048, OpenSslKeyType::RSA)->generate();
   $ecKeys = KeyPairGenerator::openSsl(
       bits: OpenSslRsaBits::BITS_2048,
       type: OpenSslKeyType::EC,
       curveName: OpenSslCurveName::PRIME256V1,
   )->generate();
   $sodiumBoxKeys = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $sodiumSignKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $autoTypeKeys = KeyPairGenerator::forType(KeyPairType::OPENSSL_RSA)->generate();

   // CsrBuilder and CertificateBuilder/Parser
   $dn = [
       'countryName' => 'US',
       'organizationName' => 'Epicrypt',
       'commonName' => 'epicrypt.local',
   ];
   $csr = CsrBuilder::openSsl()->build($dn, $rsaKeys['private']);
   $cert = CertificateBuilder::openSsl('sha512')->selfSign($dn, $rsaKeys['private'], 365);
   $parsed = CertificateParser::openSsl()->parse($cert);

   // KeyExchange
   $exchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
   $secretAB = $exchange->derive($sodiumBoxKeys['private'], KeyPairGenerator::sodium()->generate(asBase64Url: true)['public']);
   $activeBackend = $exchange->backend(); // enum KeyExchangeBackend
   $openSslExchange = KeyExchange::openSsl();
   $sodiumExchange = KeyExchange::sodium();

   // Direct backend usage (advanced)
   $sodiumDirect = new SessionKeyExchange();
   $opensslDirect = new DiffieHellman();
   $directSignKeys = (new SigningKeyPairGenerator())->generate(asBase64Url: true);

   // OpenSSL RSA interoperability
   $rsaCipher = new RsaCipher();
   $encrypted = $rsaCipher->encrypt('interop-message', $rsaKeys['public']);
   $decrypted = $rsaCipher->decrypt($encrypted, $rsaKeys['private']);
