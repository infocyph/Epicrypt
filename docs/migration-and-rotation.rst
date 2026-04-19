Migration and Rotation Cookbook
===============================

This page shows the preferred Epicrypt migration pattern once your application has:

- one active key for new writes
- one or more fallback keys for legacy reads
- a short migration window where successful fallback reads trigger re-issue or re-encryption

Core Model
----------

Use the same mental model across domains:

- active key: used for all new writes
- fallback keys: accepted only during migration
- matched key id: recorded when you need to know which candidate succeeded
- used fallback key: tells you whether the value should be rewritten under the active key

Represent that with ``KeyRing``:

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRing;

   $ring = new KeyRing([
       'legacy-2025' => $legacyKey,
       'active-2026' => $activeKey,
   ], 'active-2026');

Protected Strings
-----------------

Use ``decryptWithAnyKeyResult()`` when a protected value may have been encrypted with an older key.

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $protector = StringProtector::forProfile(SecurityProfile::MODERN);
   $result = $protector->decryptWithAnyKeyResult($ciphertext, $ring);

   $plaintext = $result->plaintext;

   if ($result->usedFallbackKey) {
       $ciphertext = $protector->reencryptWithAnyKey($ciphertext, $ring, $activeKey);
   }

Envelope-Protected Data
-----------------------

``EnvelopeProtector`` follows the same flow.

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
   $result = $protector->decryptWithAnyKeyResult($encodedEnvelope, $ring);

   if ($result->usedFallbackKey) {
       $encodedEnvelope = $protector->reencryptWithAnyKey($encodedEnvelope, $ring, $activeMasterKey);
   }

Wrapped Secrets
---------------

Wrapped secrets should also move forward when an older master key matches.

.. code-block:: php

   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   $manager = new WrappedSecretManager();
   $result = $manager->unwrapWithAnyKeyResult($wrappedSecret, $ring);

   $secret = $result->plaintext;

   if ($result->usedFallbackKey) {
       $wrappedSecret = $manager->rewrapWithAnyKey($wrappedSecret, $ring, $activeMasterSecret);
   }

JWT and Signed Payload Verification
-----------------------------------

When you only need verification metadata, prefer ``verifyWithAnyKeyResult()``.

.. code-block:: php

   $result = $jwt->verifyWithAnyKeyResult($token, $ring);

   if (!$result->verified) {
       throw new RuntimeException('Token verification failed.');
   }

   if ($result->usedFallbackKey) {
       // Re-issue the token with the active signing key when appropriate.
   }

Files
-----

Protected files should be re-encrypted into a new destination or migrated in place.

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $files = FileProtector::forProfile(SecurityProfile::MODERN);
   $result = $files->reencryptWithAnyKey(
       '/secure/archive.epc',
       '/secure/archive.current.epc',
       $ring,
       $activeFileKey,
   );

   if ($result->usedFallbackKey) {
       // The migration consumed a fallback key and is now on the active key.
   }

Operational Guidance
--------------------

- keep fallback keys only as long as legacy artifacts still exist
- rewrite on successful fallback reads when doing so is safe for your workflow
- remove old keys after the migration window closes
- prefer ``SecurityProfile::MODERN`` for new writes unless you are intentionally operating a compatibility boundary
- use ``SecurityProfile::LEGACY_DECRYPT_ONLY`` on profile-aware factories when a service should keep reading old artifacts but must stop producing new ones
