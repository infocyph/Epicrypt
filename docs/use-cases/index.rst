Use Cases
=========

This section is organized as a practical "learn by example" map.

Start with the workflow page that matches your job, then open the related example page when you want broader API coverage.

Quick Decision Matrix
---------------------

.. list-table::
   :header-rows: 1
   :widths: 38 22 40

   * - You need to...
     - Use this domain
     - Start with
   * - Secure forms, account flows, and signed browser links
     - ``Security``
     - :doc:`Web App Security <web-app-security>`
   * - Issue JWTs or opaque API tokens
     - ``Token``
     - :doc:`API and Token Security <api-and-token-security>`
   * - Protect files, blobs, or stored secrets
     - ``DataProtection`` / ``Password``
     - :doc:`File and Secret Protection <file-and-secret-protection>`
   * - Work with key pairs, CSRs, certificates, or shared-secret derivation
     - ``Certificate``
     - :doc:`PKI and Key Exchange <pki-and-key-exchange>`
   * - Reach for lower-level crypto primitives
     - ``Crypto``
     - :doc:`Crypto Complete Examples <crypto-complete-examples>`
   * - Hash content or verify file integrity
     - ``Integrity``
     - :doc:`Integrity Complete Examples <integrity-complete-examples>`
   * - Generate nonces, salts, keys, and random token material
     - ``Generate``
     - :doc:`Generate Complete Examples <generate-complete-examples>`

Learning Paths
--------------

Secure Web Applications
^^^^^^^^^^^^^^^^^^^^^^^

Use these pages for browser-facing application flows.

.. toctree::
   :maxdepth: 1

   web-app-security
   security-complete-examples
   password-complete-examples

Secure APIs and Service-to-Service Flows
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use these pages for bearer tokens, signed payloads, and API authorization boundaries.

.. toctree::
   :maxdepth: 1

   api-and-token-security
   token-complete-examples

Protect Data at Rest
^^^^^^^^^^^^^^^^^^^^

Use these pages for application payloads, file encryption, and wrapped secret material.

.. toctree::
   :maxdepth: 1

   file-and-secret-protection
   data-protection-complete-examples

Work with PKI and Trust Material
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use these pages for key generation, certificate workflows, and shared-secret derivation.

.. toctree::
   :maxdepth: 1

   pki-and-key-exchange
   certificate-complete-examples

Use Lower-Level Building Blocks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use these pages when you need direct primitives or supporting utilities.

.. toctree::
   :maxdepth: 1

   crypto-complete-examples
   integrity-complete-examples
   generate-complete-examples

Capability Guides
-----------------

If you already know the domain and just want API details, jump to the capability guides:

- :doc:`Certificate <../certificate>`
- :doc:`Crypto <../crypto>`
- :doc:`Token <../token>`
- :doc:`Password <../password>`
- :doc:`Integrity <../integrity>`
- :doc:`Generate <../generate>`
- :doc:`Data Protection <../data-protection>`
- :doc:`Security <../security>`
