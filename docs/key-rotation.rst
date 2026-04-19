Key Rotation Cookbook
=====================

This page shows the preferred Epicrypt key-rotation pattern once your application has:

- one active key for new writes
- one or more fallback keys for rollover reads
- a short rotation window where successful fallback reads trigger re-issue or re-encryption

Core Model
----------

Use the same model across domains:

- active key: used for all new writes
- fallback keys: accepted only during a rotation window
- matched key id: recorded when you need to know which candidate succeeded
- used fallback key: tells you whether the value should be rewritten under the active key

Represent that with ``KeyRing``:

.. code-block:: php

   use Infocyph\Epicrypt\Security\KeyRing;

   $ring = new KeyRing([
       'k2026-q1' => $previousKey,
       'k2026-q2' => $activeKey,
   ], 'k2026-q2');

Protected Strings
-----------------

Use ``decryptWithAnyKeyResult()`` when a protected value may have been encrypted with a previous key version.

.. code-block:: php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $protector = StringProtector::forProfile();
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

Wrapped secrets should also move forward when a previous master key matches.

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

Protected files should be re-encrypted into a new destination or rotated in place.

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
       // The file was read with a fallback key and is now on the active key.
   }

Operational Guidance
--------------------

- keep fallback keys only during an active rollover window
- rewrite on successful fallback reads when doing so is safe for your workflow
- remove retired keys after the rotation window closes
- prefer ``SecurityProfile::MODERN`` for new writes
