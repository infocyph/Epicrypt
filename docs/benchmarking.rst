Benchmarking
============

Epicrypt uses ``phpbench/phpbench`` for repeatable micro-benchmarking and also
keeps a focused authentication benchmark for protocol-path performance and
persistent-runtime memory evidence.

Benchmark Commands
------------------

.. code-block:: bash

   composer ic:bench:run
   composer ic:bench:quick
   composer ic:bench:chart
   php benchmarks/authentication.php

- ``ic:bench:quick`` is tuned for fast local checks.
- ``ic:bench:run`` is a fuller aggregate report.
- ``benchmarks/authentication.php`` records representative OAuth/OIDC/PAT
  operation timings and enforces the persistent-worker memory-growth guard used
  by the Security & Standards workflow.

Benchmark Suite Location
------------------------

Benchmarks live in:

- ``benchmarks/*Bench.php`` for PHPBench suites;
- ``benchmarks/authentication.php`` for the focused authentication/runtime
  evidence harness.

Current suite includes:

- AEAD encryption and decryption per available approved algorithm;
- JWT signing and verification per HS, RS, and ES algorithm, plus KeyRing and
  JWKS resolution;
- password hashing and verification per available supported algorithm;
- certificate/key generation and HKDF key exchange;
- stream-native file protection and integrity paths;
- 64 KiB, 256 KiB, and 1 MiB SecretStream chunk sizes;
- OAuth access-token issue/verify, authorization-code JWE, refresh-token JWE,
  DPoP issue/verify, OIDC ID-token issue/verify, PAT authoritative validation,
  fallback-key verification and repeated persistent-worker PAT validation.

Notes for Useful Numbers
------------------------

- Compare results on the same machine profile.
- Prefer relative comparison between commits over absolute numbers.
- OpenSSL key generation and RSA operations are naturally slower than symmetric
  primitives.
- Run multiple passes if you are making performance-sensitive decisions.
- Do not weaken cryptographic/protocol work to satisfy a latency number. CI
  records authentication latency as evidence; only the bounded persistent-worker
  memory-growth guard is a hard performance gate.

Typical Workflow
----------------

.. code-block:: bash

   # before changes
   composer ic:bench:quick
   php benchmarks/authentication.php

   # make changes

   # after changes
   composer ic:bench:quick
   php benchmarks/authentication.php
