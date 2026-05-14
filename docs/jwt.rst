JWT
===

JWT is covered under :doc:`token`, but this page highlights the hardening and interoperability APIs.

Highlights:

- ``SymmetricJwt`` with ``HS256/HS384/HS512``.
- ``AsymmetricJwt`` with ``RS*`` and ``ES*``.
- Structured verification results via ``verifyResult()`` / ``decodeResult()``.
- Header/claim hardening with ``JwtValidationOptions`` and expected/required claims models.
- ``decodeWithAnyKeyResult()`` / ``verifyWithAnyKeyResult()`` for rotation-aware verification metadata.
- ``AsymmetricJwt::decodeFromJwksResult()`` / ``verifyFromJwksResult()`` for JWKS-kid verification.

Result Object Fields
--------------------

``JwtVerificationResult`` provides:

- ``verified``
- ``claims``
- ``headers``
- ``matchedKeyId``
- ``usedFallbackKey``
- ``expired``
- ``notBeforeViolation``
- ``algorithm``

Use result APIs when token rejection behavior needs to branch by reason (expired vs signature mismatch, etc.).

JWKS/JWK Notes
--------------

``Token\\Jwt\\Jwks`` supports:

- export public PEM keys to JWK/JWKS
- resolve a JWK by ``kid``
- import RSA/EC JWK public keys back to PEM

With ``AsymmetricJwt``, token ``kid`` is required for JWKS verification flows.
