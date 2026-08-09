Error Handling
==============

Epicrypt provides a capability-aware exception hierarchy under:

- ``Infocyph\\Epicrypt\\Exception``

Root
----

- ``EpicryptException``

Main Capability Exceptions
--------------------------

- ``Exception\\Crypto\\CryptoException``
- ``Exception\\Token\\TokenException``
- ``Exception\\Password\\PasswordException``
- ``Exception\\Integrity\\IntegrityException``
- ``FileAccessException``
- ``ConfigurationException``

Important Specialized Exceptions
--------------------------------

Crypto:

- ``EncryptionException``
- ``DecryptionException``
- ``InvalidKeyException``
- ``InvalidNonceException``
- ``SignatureException``
- ``IntegrityCheckFailedException``

Token:

- ``InvalidTokenException``
- ``ExpiredTokenException``
- ``InvalidClaimException``
- ``UnsupportedAlgorithmException``
- ``KeyResolutionException``

Password:

- ``InvalidPasswordException``
- ``PasswordHashException``
- ``SecretProtectionException``

Integrity:

- ``HashingException``

Recommended Catch Strategy
--------------------------

- Catch specific capability exceptions when handling expected failures.
- Catch ``EpicryptException`` at service boundaries for centralized error mapping.
- Avoid broad ``Throwable`` catch unless you rethrow as domain-specific errors.

OAuth Refresh-Token Results
----------------------------

Refresh-token presentation failures are expected protocol outcomes, so
``RefreshTokenManager::rotate()`` returns ``RefreshTokenRotationResult`` rather
than throwing for an invalid, expired, reused, revoked, client-mismatched,
sender-mismatched, or scope-mismatched token. At the OAuth HTTP boundary, map
all of these statuses to the same ``invalid_grant`` response. Do not reveal
which check failed to the client.

Configuration errors and an invalid store result still throw. ``CONFLICT`` is
a digest-collision/storage-conflict result; the manager already performs its
bounded internal retries. If it remains, map it to ``invalid_grant`` with the
other presentation failures.
