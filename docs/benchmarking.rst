Benchmarking
============

Epicrypt uses ``phpbench/phpbench`` for micro-benchmarking.

Benchmark Commands
------------------

.. code-block:: bash

   composer ic:bench:run
   composer ic:bench:quick
   composer ic:bench:chart

- ``ic:bench:quick`` is tuned for fast local checks.
- ``ic:bench:run`` is a fuller aggregate report.

Benchmark Suite Location
------------------------

Benchmarks live in:

- ``benchmarks/*Bench.php``

Current suite includes:

- AEAD encryption and decryption per available approved algorithm
- JWT signing and verification per HS, RS, and ES algorithm, plus KeyRing and JWKS resolution
- password hashing and verification per available supported algorithm
- certificate/key generation and HKDF key exchange
- file encryption/decryption through Pathwise 3
- 64 KiB, 256 KiB, and 1 MiB SecretStream chunk sizes

Notes for Useful Numbers
------------------------

- Compare results on the same machine profile.
- Prefer relative comparison between commits over absolute numbers.
- OpenSSL key generation and RSA operations are naturally slower than symmetric primitives.
- Run multiple passes if you are making performance-sensitive decisions.

Typical Workflow
----------------

.. code-block:: bash

   # before changes
   composer ic:bench:quick

   # make changes

   # after changes
   composer ic:bench:quick
