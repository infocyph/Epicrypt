Certificate Domain
==================

Namespace: ``Infocyph\\Epicrypt\\Certificate``

Scope
-----

Certificate/PKI/asymmetric interoperability and key-exchange features.

Includes:

- keypair generation
- key exchange
- CSR generation
- self-signed certificate generation
- certificate parsing
- RSA interoperability helper

Key Pair Generation
-------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $openSslKeys = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();
   $sodiumBoxKeys = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $sodiumSignKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);

Return shape:

- ``['private' => string, 'public' => string]``

Key Exchange
------------

Sodium (Curve25519)
~~~~~~~~~~~~~~~~~~~

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $a = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $b = KeyPairGenerator::sodium()->generate(asBase64Url: true);

   $exchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
   $secretAB = $exchange->derive($a['private'], $b['public']);
   $secretBA = $exchange->derive($b['private'], $a['public']);

OpenSSL
~~~~~~~

.. code-block:: php

   $exchange = KeyExchange::forBackend(KeyExchangeBackend::OPENSSL);
   $shared = $exchange->derive($privatePem, $publicPem);

If you prefer direct named constructors, ``KeyExchange::sodium()`` and ``KeyExchange::openSsl()`` remain available and map to the same backend enum values.

CSR and Certificate
-------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\CsrBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateParser;

   $dn = [
       'countryName' => 'US',
       'stateOrProvinceName' => 'CA',
       'localityName' => 'San Francisco',
       'organizationName' => 'Epicrypt',
       'commonName' => 'epicrypt.local',
       'emailAddress' => 'security@epicrypt.local',
   ];

   $csrPem = CsrBuilder::openSsl()->build($dn, $privatePem);
   $certPem = CertificateBuilder::openSsl()->selfSign($dn, $privatePem, 365);
   $parsed = CertificateParser::openSsl()->parse($certPem);

RSA Interoperability
--------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;

   $rsa = new RsaCipher();
   $ciphertext = $rsa->encrypt('payload', $publicPem);
   $plaintext = $rsa->decrypt($ciphertext, $privatePem);
