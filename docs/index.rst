Epicrypt Documentation
======================

Epicrypt is a **capability-first PHP security toolkit** for modern applications.

It provides security building blocks for:

- cryptography
- token security
- password and secret protection
- integrity verification
- secure random generation
- secure data protection flows
- practical security utilities

Why Epicrypt
------------

Epicrypt keeps responsibilities separated by domain (``Crypto``, ``Token``, ``Password``, etc.) and treats OpenSSL/Sodium as implementation backends inside those domains.

This gives you:

- cleaner APIs
- safer defaults
- explicit validation behavior
- easier long-term maintainability

Documentation Map
-----------------

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting-started
   architecture
   security-recommendations
   migration-and-rotation

.. toctree::
   :maxdepth: 2
   :caption: Capability Guides

   certificate
   crypto
   token
   password
   integrity
   generate
   data-protection
   security
   complete-usage-reference

.. toctree::
   :maxdepth: 1
   :caption: Use Cases

   Overview <use-cases/index>
   use-cases/web-app-security
   use-cases/security-complete-examples
   use-cases/password-complete-examples
   use-cases/api-and-token-security
   use-cases/token-complete-examples
   use-cases/file-and-secret-protection
   use-cases/data-protection-complete-examples
   use-cases/pki-and-key-exchange
   use-cases/certificate-complete-examples
   use-cases/crypto-complete-examples
   use-cases/integrity-complete-examples
   use-cases/generate-complete-examples

.. toctree::
   :maxdepth: 2
   :caption: Operations

   error-handling
   testing-and-quality
   benchmarking

Package
-------

- Namespace root: ``Infocyph\\Epicrypt``
- PHP: ``>=8.4``
- Extensions: ``ext-sodium``, ``ext-openssl``, ``ext-json``, ``ext-mbstring``, ``ext-ctype``, ``ext-simplexml``
