Epicrypt 3.0
============

Epicrypt provides authenticated data protection, token security, password
security, integrity primitives, certificate tooling, and a transport-neutral
OAuth 2.1/OpenID Connect/personal-token core for PHP 8.4 and later.

Upgrading from Epicrypt 2.x? Start with :doc:`migration-3.0` for dependency,
API, persisted-format and deployment changes.

Complete-path examples
----------------------

- :doc:`certificate`: create a CA, issue a service certificate, and validate it
  before deployment.
- :doc:`pki-hardening`: understand the Epicrypt 3 X.509, CSR, chain, PFX, CRL
  and CMS ownership/security decisions.
- :doc:`crypto`: sign, encrypt, decrypt, and authenticate a service message.
- :doc:`data-protection`: protect a database value and renew it through key
  rotation.
- :doc:`generate`: derive purpose-isolated keys and use them for protection and
  authentication.
- :doc:`integrity`: publish and verify a signed release manifest and artifact.
- :doc:`password`: register, authenticate, and transparently rehash a password.
- :doc:`security`: issue and atomically consume a single-use password-reset
  token.
- :doc:`token`: issue/verify JWTs, rotate refresh artifacts, publish JWKS, and
  use JWS/JWE primitives safely.
- :doc:`oauth-lifecycle`: build the transport-neutral OAuth/OIDC lifecycle over
  Epicrypt's authorization, token, refresh, resource validation, revocation,
  introspection, DPoP, metadata/JWKS, and OIDC services.
- :doc:`personal-access-tokens`: provision PAT signing keys, issue credentials,
  authorize exact abilities, track usage, list metadata, and revoke one or all
  subject tokens.
- :doc:`authentication-standards`: review the exact OAuth 2.1, OIDC Core and
  Discovery standards profile, supported behavior and explicit 3.0 exclusions.
- :doc:`remote-jose-security`: deploy Remote JWKS/OpenID discovery with explicit
  DNS, redirect, timeout, cache, and SSRF boundaries.
- :doc:`token-storage`: implement durable atomic authorization-code, refresh,
  replay, revocation, access-token-status, and PAT state.
- :doc:`error-handling`: map cryptographic and protocol failures at an
  application boundary.

``Internal`` is not a consumer capability and intentionally has no public
integration example.

.. toctree::
   :maxdepth: 2

   getting-started
   migration-3.0
   architecture
   security-recommendations
   certificate
   pki-hardening
   crypto
   data-protection
   generate
   integrity
   password
   security
   token
   oauth-lifecycle
   personal-access-tokens
   authentication-standards
   remote-jose-security
   token-storage
   error-handling
   benchmarking
