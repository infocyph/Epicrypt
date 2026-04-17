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

   use-cases/web-app-security
   use-cases/api-and-token-security
   use-cases/file-and-secret-protection
   use-cases/pki-and-key-exchange

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
