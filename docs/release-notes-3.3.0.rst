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

The audit and outstanding release checks are recorded in
``docs/plans/epicrypt-3.3-release-audit-plan.md``. Local results do not certify
the final committed CI matrix or deployment performance. Merge, tag and
publication remain maintainer actions.
