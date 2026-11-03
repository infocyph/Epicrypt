Epicrypt 3.3.0 release notes
============================

This candidate adds optional Runwire 3 support, enforces JWS EC curve binding
and hardens cancellation at the remote JOSE resolver boundary. PHP remains
^8.4. Public method signatures
and persisted cryptographic formats are unchanged.

Dependencies and integration
----------------------------

* The optional Runwire development and suggested constraint is now ^3.0.
  The Composer conflict against other Runwire versions has been removed.
  Runwire remains absent from the production dependency graph.
* The production phpseclib minimum is now 4.0.3; the Pathwise development
  interoperability minimum is 4.2.1. Pathwise remains optional for consumers.
* The PSR-17 interface minimum is now psr/http-factory 1.1, which uses explicit
  nullable parameters compatible with PHP 8.4 and later.
* Development HTTP fixtures require Nyholm PSR-7 1.8.2 and HTTP mock-client
  1.6.1 or later, whose explicit nullable parameters support PHP 8.4 and 8.5
  without deprecations in lowest-dependency validation.
* Independent JOSE and OAuth/OIDC tests use Node 26.13.0 LTS, npm 12.2.1
  and jose 6.2.15. These are development tools, excluded from Composer archives.
* The matched FPM acceptance fixture installs Runwire ^3.0 for every variant.
  Runtime, request, scope, worker and event-loop ownership remain with the host.
  Both execution modes compare against published Epicrypt 3.2 by default;
  explicit reference overrides retain historical audit reproducibility.

Fixes
------

* JWS signing and verification now reject EC keys whose curve does not match
  ES256, ES384 or ES512, including the similarly sized secp256k1 curve.
  This aligns raw JWS key validation with the existing JWT policy and
  `RFC 7518 section 3.4 <https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4>`_.
* Cancellation raised by a supplied DNS resolver is propagated through both
  explicit JWKS and OpenID discovery paths. Previously, cancellation from an
  independently cancelled request could be wrapped as a resolution failure
  and return stale cached keys while the parent request remained active.
* Composer archives exclude local Graphify/PHPForge generated data and local
  AWS configuration directories.

Upgrade and validation
-----------------------

Applications opting into Runwire should install ^3.0 and follow
:doc:`runwire-integration`. The absence of a Composer conflict is not a claim
that every Runwire major is certified. Applications using the synchronous
APIs require no Runwire installation.

Validation record
------------------

The candidate passed
`Security & Standards <https://github.com/infocyph/Epicrypt/actions/runs/41561827326>`_
and `Documentation <https://github.com/infocyph/Epicrypt/actions/runs/41561827066>`_.
The security matrix recorded 43 successful jobs and two expected conditional
skips: tag-only publication and the optional Security Report. This snapshot
certifies that revision; later changes require their own validation.

* PHPForge processing, detailed QA and the release guard passed. Local
  PHP 8.5.4 ran 401 tests with 1,802 assertions; PHP 8.4.26 with libsodium
  1.0.22 ran 401 tests with 1,815 assertions, including positive AEGIS coverage.
  PHP 8.4/8.5 stable and lowest dependencies, all 15 security mutation shards,
  Windows publication, strict Sphinx and independent interoperability passed
  in CI. Configured analysis, mutation and style limits remain enforced.
* The Composer archive contained 297 entries, including all 291 tracked
  runtime files. Its SHA-256 was
  ``1f3c00b6f3357db3fb940ff1ae14f6c6cf8e521b56ac905b596922bd37cb1ac6``.
  An isolated production-only consumer passed platform, core and RSA-PSS
  smoke checks without optional Runwire, Pathwise or Ctype. Production audit
  reported zero advisories and zero abandoned packages. Development-only
  PHPBench/PHPForge dependency abandonment remains an upstream maintenance item.
* All six matched release comparisons and both identical-code controls passed
  the unchanged 2% paired median RPM loss, 5% trial spread and 256 MiB
  process-tree RSS limits. Every case completed its 300-second persistent
  soak and real FPM replacement. Together, the eight soaks verified 29,417,032
  isolated requests; maximum FPM process-tree RSS was 114,040 KiB and maximum
  persistent-process RSS was 19,688 KiB. Invalid noisy attempts were retained
  separately and excluded from qualified throughput claims.
