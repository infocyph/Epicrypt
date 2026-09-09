Epicrypt 3.0
============

Epicrypt provides authenticated data protection, token security, password
security, integrity primitives, and certificate tooling for PHP 8.4 and later.

Complete-path examples
----------------------

- :doc:`certificate`: create a CA, issue a service certificate, and validate it
  before deployment.
- :doc:`crypto`: sign, encrypt, decrypt, and authenticate a service message.
- :doc:`data-protection`: protect a database value and renew it through key
  rotation.
- :doc:`generate`: derive purpose-isolated keys and use them for protection and
  authentication.
- :doc:`integrity`: publish and verify a signed release manifest and artifact.
- :doc:`password`: register, authenticate, and transparently rehash a password.
- :doc:`security`: issue and atomically consume a single-use password-reset
  token.
- :doc:`oauth-lifecycle`: issue and verify access tokens, rotate refresh tokens,
  bind DPoP, narrow scopes, and revoke authorization.
- :doc:`remote-jose-security`: deploy Remote JWKS/OpenID discovery with explicit
  DNS, redirect, timeout, cache, and SSRF boundaries.
- :doc:`error-handling`: map cryptographic failures at an application boundary.

``Internal`` is not a consumer capability and intentionally has no public
integration example.

.. toctree::
   :maxdepth: 2

   getting-started
   architecture
   security-recommendations
   certificate
   crypto
   data-protection
   generate
   integrity
   password
   security
   token
   oauth-lifecycle
   remote-jose-security
   token-storage
   error-handling
   benchmarking
