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
