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

Representative host RPM acceptance
----------------------------------

The CI PHPBench jobs are *component evidence*, not production-equivalent
throughput certification. For 3.2, use a matched PHP-FPM (or an explicitly
supported persistent-host) deployment of baseline and candidate on the same
class of hardware with the same concurrency, routes, service topology,
Composer dependency versions, PHP version, OPcache configuration and warm-up.
The endpoints must run identical request workloads and return independently
validated correct responses. Do not compare unmatched or changing hosts.

The version-controlled ``benchmarks/host-rpm-compare.sh`` harness requires
``wrk``, ``curl``, Bash, Awk, Sort and Ps. Its two positional arguments
are the identical baseline/candidate endpoint URLs, and the mandatory PID
environment variables identify the respective PHP-FPM/server master processes
for process-tree resident-memory sampling:

.. code-block:: bash

   HOST_BASE_PID=1234 HOST_CANDIDATE_PID=5678 \
     HOST_EXPECTED_BODY=ok HOST_ROUNDS=5 \
     HOST_CONNECTIONS=16 HOST_DURATION=20s \
     HOST_REPORT=host-performance.tsv \
     bash benchmarks/host-rpm-compare.sh \
       http://127.0.0.1:8101/representative \
       http://127.0.0.1:8102/representative

Run the comparison separately for unbound and borrowed Runwire calls, file
streams, cancellation, remote JOSE cache hits/misses and any relevant
application-layer route. Each comparison alternates baseline/candidate order and checks a 2%
median **correct-response** RPM regression budget. Supply a fixed,
independently verified ``HOST_EXPECTED_BODY``: the wrk Lua
``host-rpm-validate.lua`` callback checks **every** measured response
for exact HTTP 200 status and matching body. Missing/mismatched responses,
redirects, connection errors and timeouts fail the comparison. The harness
records p50/p95/p99 latency and peak summed process-tree RSS per sample.

The endpoint must return the *same correct deterministic response* for each
request. For dynamic OAuth/JOSE application paths, expose a representative
deterministic validation route or use a workload-specific validator that
performs equivalent verification; never silently accept successful status
alone. Full production release certification still requires matched deployed
hosts, independent workload correctness validation and sustained resource
monitoring. The comparator also has four fail-closed parser regression cases
exercised in the Security & Standards workflow.

Record the host profile, full PHP/Composer/OPcache versions and configuration,
CPU/memory headroom, worker counts, concurrency, elapsed test duration,
timeouts, errors, p50/p95/p99, live process-tree memory, request validation,
variation across runs, and the complete ``host-performance.tsv`` for
each scenario. Results on shared GitHub Actions runners or from CLI-only
microbenchmarks are not substitutes for production-equivalent host evidence.

Persistent Runwire host acceptance also runs in CI on PHP 8.4 and 8.5:
``tests/Smoke/persistent-runwire-host.php`` validates 2,000 long-lived
request operations per process after warmup, alternating isolated tenants,
cancelled sibling requests, closed request reuse, heap-growth bounds, and a
fresh-process replacement. That test does not claim to implement a deployed
Swoole server or prove PHP-FPM deployment semantics.
