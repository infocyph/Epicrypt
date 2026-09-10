Epicrypt 3 PKI hardening
========================

Epicrypt 3 deliberately uses two certificate backends for different jobs rather
than hiding either behind a lowest-common-denominator abstraction.

* phpseclib 4 is the portable parser/model boundary for X.509, CSR and PFX
  import/validation.
* OpenSSL remains the accelerated key-generation, certificate-issuance,
  purpose-aware chain-verification and interoperable PKCS#12 serialization
  backend.
* Public Epicrypt APIs return strings, arrays, enums and Epicrypt exceptions;
  phpseclib/OpenSSL implementation objects are not part of the public contract.

This split keeps ``ext-openssl`` mandatory in Epicrypt 3. Removing the extension
would currently remove certificate issuance, native key generation, the
explicit purpose-aware chain verifier and the PKCS#12 export backend, so making
it optional would be false modularity rather than a useful capability split.

Portable X.509 and CSR inspection
----------------------------------

``CertificateInspector`` and ``CsrInspector`` parse bounded inputs through
phpseclib 4. The CSR inspector also verifies the CSR's self-signature before
returning metadata. They expose no phpseclib object.

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\Certificate\CertificateInspector;
   use Infocyph\Epicrypt\Certificate\CsrInspector;

   $csrInfo = new CsrInspector()->inspect($csrPem);
   $certificateInfo = new CertificateInspector()->inspect($certificatePem);

   if (!hash_equals($csrInfo['public_key'], $certificateInfo['public_key'])) {
       throw new RuntimeException('Issued certificate key does not match the CSR.');
   }

The existing OpenSSL builders remain useful issuance accelerators. Epicrypt's
tests deliberately generate certificates and CSRs with OpenSSL and parse them
with phpseclib 4 so backend compatibility is continuously exercised.

Explicit chain validation
-------------------------

``CertificateChainVerifier`` separates trust anchors from untrusted
intermediates. The caller owns trust selection; Epicrypt never discovers CAs,
follows AIA URLs or mutates a process-global trust registry.

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\Certificate\CertificateChainVerifier;
   use Infocyph\Epicrypt\Certificate\Enum\CertificatePurpose;

   $valid = new CertificateChainVerifier()->verify(
       $leafCertificatePem,
       [$trustedRootPem],
       CertificatePurpose::SSL_SERVER,
       [$intermediatePem],
   );

Each certificate is bounded and parsed before OpenSSL verification. Trust
anchors and intermediates are count-bounded, duplicate intermediate/anchor
entries are rejected, and at most one temporary trust bundle plus one temporary
intermediate bundle is created. Temporary bundles are created with restrictive
permissions where supported and are removed in ``finally``.

A successful chain/purpose result is not hostname verification. The TLS/HTTP
client that owns the connection must still verify the peer DNS name or IP.

PFX / PKCS#12
-------------

``Pkcs12`` uses phpseclib 4 as the bounded PFX parser/model and OpenSSL as the
container serializer. The split is deliberate: CI interoperability testing
showed that OpenSSL serialization is the portable output boundary required for
third-party PKCS#12 consumers, while phpseclib provides the cleaner bounded
import/model API. Every exported OpenSSL container is loaded again through
phpseclib before it is returned.

The public API bounds the whole container, certificate count, PEM inputs,
password size and friendly-name size. Export proves that the private key matches
the leaf certificate before serialization. Import normalizes the PFX after
password verification, requires exactly one supported private key and a matching
certificate, returns an unencrypted PKCS#8 private key, and preserves the CA
certificate set and available friendly-name metadata.

Tests cover both directions: Epicrypt-generated/OpenSSL-serialized PFX is read
by phpseclib and OpenSSL, while OpenSSL-generated PKCS#12 is imported through
Epicrypt's phpseclib boundary. Wrong passwords, mismatched keys and oversized
inputs fail through stable Epicrypt exceptions without exposing key material.

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\Certificate\Pkcs12;

   $pfx = new Pkcs12()->export(
       $leafCertificatePem,
       $leafPrivateKeyPem,
       $pfxPassword,
       privateKeyPassphrase: $privateKeyPassphrase,
       friendlyName: 'orders-service',
       caCertificatesPem: [$intermediatePem, $rootPem],
   );

   $material = new Pkcs12()->import($pfx, $pfxPassword);

CRL decision for 3.0
--------------------

phpseclib 4 provides a first-class CRL parser, but its convenience
``CRL::validateSignature()`` resolves issuers through phpseclib's static CA
store. Epicrypt 3 intentionally does not wrap that API because doing so would
reintroduce process-global trust state and create ambiguous behavior in
persistent workers and Fiber-based applications.

Therefore Epicrypt 3 does **not** ship a first-class CRL verifier. Applications
may provide already-validated revocation decisions at their PKI/TLS boundary.
A future Epicrypt CRL API is acceptable only if it can take the issuer and CRL
explicitly, validate the signature/key usage without shared mutable trust
state, bound the revoked-entry corpus, and perform no hidden network access.
OCSP and AIA fetching remain outside core.

CMS decision for 3.0
--------------------

phpseclib 4 has first-class CMS support, but Epicrypt currently has no concrete
consumer requiring a CMS sign/verify/encrypt/decrypt surface. Shipping one in
3.0 would materially expand parser, interoperability and misuse surface without
helping Foundation's current integration goal. CMS is therefore intentionally
not exposed in Epicrypt 3.0. It can be reconsidered when a concrete consumer can
supply independent fixtures and a bounded profile.

Performance and backend choice
------------------------------

``CertificateBench`` records OpenSSL certificate parsing beside phpseclib
``CertificateInspector`` parsing, native OpenSSL key generation and bounded PFX
import. These measurements are attribution data, not permission to weaken
validation or bounds. OpenSSL remains preferred where it supplies a mature,
interoperable accelerated operation; phpseclib is preferred where its portable
typed parser/model removes unsafe or ambiguous backend behavior.
