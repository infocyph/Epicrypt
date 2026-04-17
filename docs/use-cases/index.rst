Overview
========

This section answers one practical question first:

**"Which Epicrypt feature should I use for my job?"**

Quick Decision Matrix
---------------------

.. list-table::
   :header-rows: 1
   :widths: 40 25 35

   * - You need to...
     - Use this domain
     - Start with
   * - Encrypt app payloads with authenticated encryption
     - ``Crypto``
     - ``AeadCipher``
   * - Encrypt/decrypt large files
     - ``DataProtection``
     - ``FileProtector``
   * - Sign and verify JWTs
     - ``Token``
     - ``SymmetricJwt`` or ``AsymmetricJwt``
   * - Issue revocation-friendly opaque tokens
     - ``Token``
     - ``OpaqueToken``
   * - Hash and verify passwords
     - ``Password``
     - ``PasswordHasher``
   * - Evaluate password quality
     - ``Password``
     - ``PasswordStrength``
   * - Hash files/content and verify digests
     - ``Integrity``
     - ``FileHasher``, ``StringHasher``, ``DigestVerifier``
   * - Generate nonces/salts/key material
     - ``Generate``
     - ``NonceGenerator``, ``SaltGenerator``, ``KeyMaterialGenerator``
   * - Build CSRF/reset/remember/action/email tokens
     - ``Security``
     - ``CsrfTokenManager``, ``PasswordResetToken``, ``RememberToken``, ``ActionToken``, ``EmailVerificationToken``
   * - Generate/verify signed links
     - ``Security``
     - ``SignedUrl``
   * - Handle key exchange / CSR / cert generation/parsing
     - ``Certificate``
     - ``KeyExchange``, ``CsrBuilder``, ``CertificateBuilder``, ``CertificateParser``

Practical Flows
---------------

.. toctree::
   :maxdepth: 2

   web-app-security
   api-and-token-security
   file-and-secret-protection
   pki-and-key-exchange

Next
----

- Use these flow pages for implementation choices.
- Use capability guides for API details:
  - :doc:`Certificate <../certificate>`
  - :doc:`Crypto <../crypto>`
  - :doc:`Token <../token>`
  - :doc:`Password <../password>`
  - :doc:`Integrity <../integrity>`
  - :doc:`Generate <../generate>`
  - :doc:`Data Protection <../data-protection>`
  - :doc:`Security <../security>`
