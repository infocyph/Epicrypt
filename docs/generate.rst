Secure generation and key derivation
====================================

All generators use cryptographically secure operating-system randomness.
``KeyMaterialGenerator`` returns Base64URL by default so keys can be stored in a
secret manager without corrupting binary bytes.

Complete path: derive and use purpose-isolated application keys
----------------------------------------------------------------

Store one random root key and derive stable subkeys for independent purposes.
The context and subkey IDs become part of the long-lived key contract: changing
them makes existing protected data unreadable or unverifiable.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Crypto\Mac;
   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDerivationContext;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   // Provision once and store only in the deployment secret manager.
   $rootKey = new KeyMaterialGenerator()->forMasterSecret();
   $context = new KeyDerivationContext(sodiumContext: 'APPKEY01');
   $deriver = new KeyDeriver();
   $customerDataKey = $deriver->subkey($rootKey, 1, context: $context);
   $auditMacKey = $deriver->subkey($rootKey, 2, context: $context);

   $options = new ProtectionOptions(
       'customer/profile/v1',
       'tenant=42;customer=1847',
   );
   $protector = StringProtector::create();
   $protectedProfile = $protector->protect(
       json_encode(['email' => 'alice@example.test'], JSON_THROW_ON_ERROR),
       $customerDataKey,
       $options,
   );
   $mac = new Mac();
   $auditTag = $mac->generate($protectedProfile, $auditMacKey);

   if (!$mac->verify($protectedProfile, $auditTag, $auditMacKey)) {
       throw new RuntimeException('Audit record authentication failed.');
   }
   $profile = json_decode(
       $protector->unprotect($protectedProfile, $customerDataKey, $options),
       true,
       flags: JSON_THROW_ON_ERROR,
   );

Use different eight-byte contexts for different applications, and different
numeric IDs for purposes within one application. Rotate the root through an
explicit data-migration plan; do not silently replace it.

Generate purpose-sized material
-------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
   use Infocyph\Epicrypt\Generate\NonceGenerator;
   use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
   use Infocyph\Epicrypt\Generate\SaltGenerator;

   $keys = new KeyMaterialGenerator();
   $databaseFieldKey = $keys->forAead();
   $fileStreamKey = $keys->forSecretStream();
   $refreshToken = new TokenMaterialGenerator()->generate();
   $passwordSalt = new SaltGenerator()->generate();
   $protocolNonce = new NonceGenerator()->generate();
   $rawChallenge = new RandomBytesGenerator()->bytes(32);
   $traceId = new RandomBytesGenerator()->string(32, prefix: 'trace_');

Use ``RandomBytesGenerator::bytes()`` only when the protocol specifies an exact
raw-byte length. Nonces and salts are not interchangeable with secret keys.

Derive isolated keys from one root key
--------------------------------------

This recipe gives two subsystems independent keys while keeping only one root
key in the deployment secret manager. The Sodium KDF context is exactly eight
bytes and the numeric IDs must remain stable for the lifetime of stored data.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDerivationContext;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $rootKey = new KeyMaterialGenerator()->forMasterSecret();
   $deriver = new KeyDeriver();
   $context = new KeyDerivationContext(sodiumContext: 'EPAPP001');

   $customerDataKey = $deriver->subkey($rootKey, subkeyId: 1, context: $context);
   $auditLogKey = $deriver->subkey($rootKey, subkeyId: 2, context: $context);

   if (hash_equals($customerDataKey, $auditLogKey)) {
       throw new RuntimeException('Purpose-isolated subkeys must differ.');
   }

For HKDF, set a unique non-empty ``info`` value for each purpose. For password
derivation, ``deriveFromPassword()`` uses Argon2id and expects a Sodium pwhash
salt; do not substitute fast HKDF for password stretching.
