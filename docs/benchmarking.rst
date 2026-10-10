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
monitoring. The comparator also has six fail-closed parser regression cases
exercised in the Security & Standards workflow.

Record the host profile, full PHP/Composer/OPcache versions and configuration,
CPU/memory headroom, worker counts, concurrency, elapsed test duration,
timeouts, errors, p50/p95/p99, live process-tree memory, request validation,
variation across runs, and the complete ``host-performance.tsv`` for
each scenario. Results on shared GitHub Actions runners or from CLI-only
microbenchmarks are not substitutes for production-equivalent host evidence.

Docker PHP-FPM acceptance
-------------------------

For a Docker-equivalent deployment, run the matched FPM fixture:

.. code-block:: bash

   HOST_DOCKER_REPORT=var/docker-host-acceptance \
     bash benchmarks/docker-host-acceptance.sh

All fixture containers use Alpine: digest-pinned PHP 8.4 FPM for the HTTP
variants and persistent process, and digest-pinned Nginx Alpine with Bash,
curl, wrk, procps and coreutils for the proxy and measurement client.
The procps implementation supplies numeric process-tree RSS in KiB;
BusyBox memory units are unsuitable for the RSS guard. Image identities
and runtime configuration are retained with every report.

The fixture installs one identical production dependency set, including
host-owned Runwire 2.1.1 and Nyholm PSR-7. It deploys four static FPM workers
per variant with identical OPcache settings, warms each variant for 60 seconds, then runs
three alternating 20-second trials at concurrency 1, 4 and 8. CPU affinity
separates FPM (cores 2,3), the proxy (core 0) and the load generator (core 1);
override ``HOST_FPM_CPUS``, ``HOST_PROXY_CPUS`` and ``HOST_CLIENT_CPUS`` for
the host's available CPU set. ``HOST_PHP_IMAGE`` selects an alternative FPM
image; ``HOST_TOOLS_IMAGE`` reuses a prepared measurement image. Overrides
define a separate deployment profile and must be recorded with its evidence.
Temporary file outputs use an identical bounded 128 MiB tmpfs per variant;
request access logs are disabled while error logs remain available. This
profile measures a Docker deployment with ephemeral memory-backed staging,
and does not certify disk or external storage throughput.

Each response validates a 64 KiB-class atomic file-protection round trip,
integrity, JWT verification, and a JWKS cache miss and hit through an in-memory
PSR-18 fixture. Borrowed calls also verify cancellation and request ownership.
This measures Epicrypt's remote boundary overhead, not external network latency.
Unbound calls compare against tag 3.1; borrowed calls compare against the
pre-remediation Runwire implementation at ``1b034ec``. Every measured response
must exactly match the independently defined result. The unchanged 2% median
RPM and 256 MiB process-tree RSS budgets apply. Evidence includes raw trials,
latencies, image identities, PHP configuration, the host dependency lock,
and the public EC key/JWKS shared by the three variants within that run.
The comparator rejects trial spreads above 5% before evaluating the RPM budget.
The same fixture runs independently in CI and preserves its raw evidence as
an artifact; the Docker-authorized host remains the production-equivalent
acceptance environment.
The independent CI deployment uses native ARM, four static FPM workers and
60-second measured trials with the same budgets. CI pins benchmark controllers
and Docker daemon threads to CPUs 0,1, separating them from FPM CPUs 2,3.
This changes only the ephemeral CI runner; the local script never changes host
daemon affinity. Interpret each deployment's
baseline/candidate comparison within its recorded architecture and CPU profile.

For a sustained persistent-process check, set
``EPICRYPT_HOST_SOAK_SECONDS=300`` when running
``tests/Smoke/persistent-runwire-host.php``. Its default remains a short smoke.
The smoke also checks 20,000 discarded bindings within one live coroutine task
against the existing 2 MiB heap-growth budget.

Persistent Runwire host acceptance also runs in CI on PHP 8.4 and 8.5:
``tests/Smoke/persistent-runwire-host.php`` validates 2,000 long-lived
request operations per process after warmup, alternating isolated tenants,
cancelled sibling requests, closed request reuse, heap-growth bounds, and a
fresh-process replacement. That test does not claim to implement a deployed
Swoole server or prove PHP-FPM deployment semantics.
