Benchmarking
============

Epicrypt uses ``phpbench/phpbench`` for micro-benchmarking.

Benchmark Commands
------------------

.. code-block:: bash

   composer bench:run
   composer bench:quick
   composer bench:chart

- ``bench:quick`` is tuned for fast local checks.
- ``bench:run`` is a fuller aggregate report.

Benchmark Suite Location
------------------------

Benchmarks live in:

- ``benchmarks/*Bench.php``

Current suite includes capability-level benchmarks for:

- ``Crypto``
- ``Token``
- ``Security``
- ``Generate``
- ``Certificate``

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
   composer bench:quick

   # make changes

   # after changes
   composer bench:quick
