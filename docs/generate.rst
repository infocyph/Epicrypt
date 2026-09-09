Secure generation and key derivation
====================================

All generators use cryptographically secure operating-system randomness.
``KeyMaterialGenerator`` measures requested lengths in raw entropy bytes and
then applies an explicit ``KeyMaterialEncoding``. Base64URL is the default for
safe secret-manager storage; RAW is for binary crypto APIs; HEX is useful for
environment/configuration values that require hexadecimal text.

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
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   // Provision once and store only in the deployment secret manager.
   $rootKey = new KeyMaterialGenerator()->forMasterSecret();
   $deriver = new KeyDeriver();
   $customerDataKey = $deriver->subkey($rootKey, 1, context: 'APPKEY01');
   $auditMacKey = $deriver->subkey($rootKey, 2, context: 'APPKEY01');

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

   use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyMaterialEncoding;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
   use Infocyph\Epicrypt\Generate\NonceGenerator;
   use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
   use Infocyph\Epicrypt\Generate\SaltGenerator;

   $keys = new KeyMaterialGenerator();
   $databaseFieldKey = $keys->forAead();
   $fileStreamKey = $keys->forSecretStream();
   $binaryKey = $keys->forMasterSecret(KeyMaterialEncoding::RAW);
   $environmentTokenSecret = $keys->forTokenSecret(KeyMaterialEncoding::HEX);
   $refreshToken = new TokenMaterialGenerator()->generate();
   $passwordSalt = new SaltGenerator()->generate();
   $protocolNonce = new NonceGenerator()->generate();
   $rawChallenge = new RandomBytesGenerator()->bytes(32);
   $traceId = new RandomBytesGenerator()->string(32, prefix: 'trace_');

``forMasterSecret()`` and ``forTokenSecret()`` both provide 32 raw bytes of
entropy before encoding. Therefore their HEX form is exactly 64 lowercase hex
characters and their Base64URL form decodes to exactly 32 bytes. Encoding does
not increase entropy. Keep the generated value in a deployment secret manager
or restricted environment file; do not log it.

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

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $rootKey = new KeyMaterialGenerator()->forMasterSecret();
   $deriver = new KeyDeriver();
   $customerDataKey = $deriver->subkey($rootKey, subkeyId: 1, context: 'EPAPP001');
   $auditLogKey = $deriver->subkey($rootKey, subkeyId: 2, context: 'EPAPP001');

   if (hash_equals($customerDataKey, $auditLogKey)) {
       throw new RuntimeException('Purpose-isolated subkeys must differ.');
   }

``subkey()`` and ``hkdf()`` accept and return Base64URL key material;
``subkeyBinary()`` and ``hkdfBinary()`` are the explicit raw-byte variants.
HKDF supports only ``HkdfAlgorithm::SHA256``, ``SHA384``, and ``SHA512`` and
defaults to SHA-256; set a unique non-empty ``info`` value for each purpose.
``deriveFromPassword()`` uses
Argon2id with a Base64URL Sodium pwhash salt, while
``deriveBinaryFromPassword()`` is the raw-byte variant. Never substitute fast
HKDF for password stretching.
