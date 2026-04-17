PKI and Key Exchange Flow
=========================

Use this flow for asymmetric interoperability, certificate lifecycle, and shared-secret derivation.

Brief
-----

The ``Certificate`` domain groups key pairs, CSRs, certificates, and shared-secret derivation in one place. Use it when trust material has to move between systems, libraries, or deployment boundaries.

Choose the Capability
---------------------

- ``Certificate\KeyPairGenerator`` for OpenSSL or sodium keypairs.
- ``Certificate\KeyExchange`` for shared-secret derivation.
- ``Certificate\CsrBuilder`` for CSR generation.
- ``Certificate\CertificateBuilder`` for certificate creation/self-signing.
- ``Certificate\CertificateParser`` for reading certificate fields.

Backend Selection
-----------------

``KeyExchange`` now supports explicit backend selection with enum selectors:

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
   use Infocyph\Epicrypt\Certificate\KeyExchange;

   $sodiumExchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
   $openSslExchange = KeyExchange::forBackend(KeyExchangeBackend::OPENSSL);

Named constructors are still available:

- ``KeyExchange::sodium()``
- ``KeyExchange::openSsl()``

Learn by Example
----------------

Scenario: generate a server key pair, create a CSR, self-sign a certificate for local development, then inspect the result.

Minimal CSR + Certificate Example
---------------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateParser;
   use Infocyph\Epicrypt\Certificate\CsrBuilder;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $keys = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();

   $dn = [
       'countryName' => 'US',
       'organizationName' => 'Epicrypt',
       'commonName' => 'example.local',
   ];

   // Build the CSR first if you need CA signing later.
   $csr = CsrBuilder::openSsl()->build($dn, $keys['private']);

   // Self-sign for local development or internal testing.
   $cert = CertificateBuilder::openSsl()->selfSign($dn, $keys['private'], 365);
   $parsed = CertificateParser::openSsl()->parse($cert);

Related Pages
-------------

- For fuller PKI and key-exchange coverage, see :doc:`Certificate Complete Examples <certificate-complete-examples>`.
- For application-level signed payloads and JWTs, see :doc:`API and Token Security <api-and-token-security>`.

Avoid
-----

- using OpenSSL RSA mode while also passing EC curve selectors
- mixing sodium box/sign key material with OpenSSL PEM keys in one call path
