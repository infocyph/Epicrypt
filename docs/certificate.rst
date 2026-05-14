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
- CA signing
- certificate parsing
- certificate utility helpers
- PEM normalization and PKCS#12 conversion
- RSA interoperability helper

Key Pair Generation
-------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $openSslKeys = KeyPairGenerator::openSsl()->generate();
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

CA Signing with SAN Options
---------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\CertificateAuthority;
   use Infocyph\Epicrypt\Certificate\CertificateOptions;

   $options = new CertificateOptions(
       days: 365,
       sanDns: ['api.example.com', 'example.com'],
       keyUsage: ['digitalSignature', 'keyEncipherment'],
       extendedKeyUsage: ['serverAuth'],
   );

   $issuedCertPem = CertificateAuthority::openSsl()->signCsr(
       $csrPem,
       $caCertificatePem,
       $caPrivateKeyPem,
       $options,
       passphrase: null,
   );

Certificate Utilities
---------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\CertificateChainVerifier;
   use Infocyph\Epicrypt\Certificate\CertificateExpiry;
   use Infocyph\Epicrypt\Certificate\CertificateFingerprint;
   use Infocyph\Epicrypt\Certificate\CertificateKeyMatcher;

   $fingerprint = (new CertificateFingerprint())->fingerprint($certPem, 'sha256');
   $expiresAt = (new CertificateExpiry())->expiresAt($certPem);
   $isExpired = (new CertificateExpiry())->isExpired($certPem, 60);
   $keyMatches = (new CertificateKeyMatcher())->privateKeyMatches($certPem, $privatePem);
   $chainOk = (new CertificateChainVerifier())->verify($certPem, [$caCertificatePem]);

PEM Normalization and PKCS#12
-----------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\PemNormalizer;
   use Infocyph\Epicrypt\Certificate\Pkcs12;

   $normalizedPem = (new PemNormalizer())->normalize($certPem);

   $pkcs12 = new Pkcs12();
   $bundle = $pkcs12->export($certPem, $privatePem, 'p12-password');
   $imported = $pkcs12->import($bundle, 'p12-password');

RSA Interoperability
--------------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;

   $rsa = new RsaCipher();
   $ciphertext = $rsa->encrypt('payload', $publicPem);
   $plaintext = $rsa->decrypt($ciphertext, $privatePem);
