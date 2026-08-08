Certificates and key exchange
=============================

RSA key generation defaults to 3072 bits and never permits RSA-1024. Certificate
options use enums for digest, key usage, and extended key usage. DNS, IP, email,
validity, and OpenSSL configuration values are validated before interpolation.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateOptions;
   use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;

   $keys = KeyPairGenerator::openSsl()->generate();
   $options = new CertificateOptions(
       days: 90,
       sanDns: ['api.example.test'],
       keyUsage: [KeyUsage::DIGITAL_SIGNATURE],
   );
   $certificate = new CertificateBuilder()->selfSign(
       ['commonName' => 'api.example.test'],
       $keys['private'],
       options: $options,
   );

``KeyExchange`` feeds the raw agreement secret through HKDF. Always supply a
non-empty, application-specific derivation context.
