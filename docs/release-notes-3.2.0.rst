Epicrypt 3.2.0 release notes
============================

These notes describe the Epicrypt 3.2.0 release candidate against the
immediately preceding ``3.1`` tag. They do not indicate that a GitHub release
has been published.

Security and correctness
------------------------

* Single-use symmetric and asymmetric JWT replay records now remain valid
  throughout the verifier's accepted expiry-and-leeway window. DPoP replay
  retention also covers its inclusive oldest accepted second.
* Remote JOSE destination checks require public-unicast IPv4/IPv6 addresses,
  including DNS answer sets and IPv4-mapped addresses. Multicast, reserved,
  shared and benchmark networks are rejected before transport invocation.
* Integrity verification and JWT JSON parsing no longer depend on an
  undeclared Ctype extension.
* Remote JWKS cache keys use a PSR-16-compatible, versioned SHA-256 identity
  incorporating destination-trust, freshness, stale and response-size policies.
  Cache backends with strict key validation are supported.
* Remote JOSE responses reject stalled body streams instead of reading
  indefinitely; existing byte and JSON complexity bounds remain enforced.
* Stale JWKS fallback checks expiry after a failed fetch. HTTP, cache and
  caller-supplied clock cancellation retain the host's cancellation exception.
* Integrity hashing rejects cancellation during the final EOF read.
  Borrowed coroutine bindings use weak task-local snapshots to prevent
  accumulation in long-lived tasks while preserving sibling isolation.

Integration and platform compatibility
--------------------------------------

* PHP 8.4 or 8.5 is supported, with Hash, JSON, OpenSSL and Sodium required.
* Optional Runwire 2.1.1 integration adds explicit borrowed-context
  cancellation and coroutine checkpoints to stream, file and remote JOSE
  operations. Existing calls without a context remain synchronous. Runwire
  is not a mandatory production dependency, and Epicrypt never owns host
  requests, workers, schedulers or event loops.
* Pathwise 4.2 is the development interoperability baseline only; there is
  no production Pathwise dependency.
* PHPForge complexity and Rector findings were resolved without weakening
  the configured analysis, mutation or style thresholds.

Upgrade and operational notes
-----------------------------

* Hosts with durable single-use JWT/replay or denylist stores must retain
  replay and revocation state for the entire accepted window, including any
  configured leeway. Audit externally written denylist record retention.
* JWKS cache keys have changed namespace. Expect an initial cold fetch on
  upgrade; equivalent trust policies may share a namespace, but deployments
  with different resolver, transport or egress guarantees must isolate caches.
* Remote JOSE requires host-configured HTTP timeouts, redirect suppression
  and connected-socket DNS pinning when rebinding protection is needed.
  Epicrypt's preflight DNS validation cannot prove where an arbitrary
  PSR-18 transport actually connected.
* Caller-owned output streams still require host publication/rollback policy.
  Local-file APIs preserve atomic staging and recheck Runwire cancellation
  before replacing the destination.
* Applications remain responsible for rate limiting, password-cost
  provisioning, durable authorization state, request lifecycle ownership and
  permissions.

Release verification
--------------------

The development PR validates PHPForge static and runtime suites, security
mutation floors, independent JOSE/OAuth interoperability, Windows publication,
AEGIS, documentation and PHPBench evidence. Final production-equivalent
successful-request throughput, persistent-host memory/isolation and controlled
release-tag verification must be recorded separately before publication.
