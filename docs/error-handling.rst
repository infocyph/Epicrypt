Error Handling
==============

Epicrypt provides a capability-aware exception hierarchy under:

- ``Infocyph\\Epicrypt\\Exception``

Complete path: map a protected read at the service boundary
-----------------------------------------------------------

Catch precise failures where the application can make a safe decision. Return
generic client messages while retaining structured internal diagnostics that
do not contain ciphertext, keys or plaintext.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Exception\ConfigurationException;
   use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
   use Infocyph\Epicrypt\Exception\EpicryptException;

   try {
       $profile = StringProtector::create()->unprotect(
           $storedCiphertext,
           $dataProtectionKey,
           new ProtectionOptions('customer/profile/v1', 'tenant=42;customer=1847'),
       );
   } catch (DecryptionException $exception) {
       $securityEvents->protectedPayloadRejected('customer/profile/v1');
       throw new RuntimeException('Stored profile is unavailable.');
   } catch (ConfigurationException $exception) {
       $operations->reportDeploymentConfigurationFailure($exception);
       throw new RuntimeException('Service configuration is invalid.');
   } catch (EpicryptException $exception) {
       $operations->reportCryptographicFailure($exception);
       throw new RuntimeException('Security operation failed.');
   }

Do not retry deterministic authentication or configuration failures. Retry
only an independently identified transient storage or network operation, with
an explicit bound and idempotency protection where required.

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
