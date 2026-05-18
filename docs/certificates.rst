Certificates
============

Canonical capability guide for certificate/PKI operations.

For complete domain-level reference and examples, see :doc:`certificate`.

Includes:

- Key pair generation.
- CSR and certificate building.
- SAN support via ``CertificateOptions``.
- CA signing.
- Utility helpers (fingerprint, expiry, key match, chain verify, PEM normalize).
- PKCS#12 export/import.

Quick Example
-------------

.. code-block:: php

   use Infocyph\Epicrypt\Certificate\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateOptions;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;

   $keys = KeyPairGenerator::openSsl()->generate();
   $dn = [
       'countryName' => 'US',
       'stateOrProvinceName' => 'CA',
       'localityName' => 'San Francisco',
       'organizationName' => 'Epicrypt',
       'commonName' => 'api.example.local',
       'emailAddress' => 'security@example.local',
   ];

   $cert = CertificateBuilder::openSsl()->selfSign(
       $dn,
       $keys['private'],
       options: new CertificateOptions(sanDns: ['api.example.local']),
   );
