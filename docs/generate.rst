Secure generation and key derivation
====================================

All generators use cryptographically secure operating-system randomness.
``KeyMaterialGenerator`` returns Base64URL by default so keys can be stored in a
secret manager without corrupting binary bytes.

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
