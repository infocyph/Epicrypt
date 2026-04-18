Password Domain
===============

Namespace: ``Infocyph\\Epicrypt\\Password``

Scope
-----

- password generation and policy
- password hashing and verification
- password rehash lifecycle
- master secret generation
- wrapped secret protection
- wrapped secret rotation and rewrap flows
- secure secret serialization

Password Generator
------------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;

   $generator = new PasswordGenerator();

   $password = $generator->generate(16, [
       'min_length' => 12,
       'require_upper' => true,
       'require_lower' => true,
       'require_digit' => true,
       'require_symbol' => true,
       'include_ambiguous' => false,
   ]);

Password Hasher
---------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;

   $hasher = new PasswordHasher();
   $hash = $hasher->hashPassword('MyStrongPassword!2026');
   $isValid = $hasher->verifyPassword('MyStrongPassword!2026', $hash);

You can tune hashing options:

.. code-block:: php

   $hash = $hasher->hashPassword('password', [
       'algorithm' => PasswordHashAlgorithm::ARGON2ID,
       'memory_cost' => 65536,
       'time_cost' => 4,
       'threads' => 2,
   ]);

Password Rehash Lifecycle
-------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $hasher = new PasswordHasher();
   $result = $hasher->verifyAndRehash('password', $storedHash, [
       'profile' => SecurityProfile::MODERN,
   ]);

   if ($result->verified && $result->rehashedHash !== null) {
       $storedHash = $result->rehashedHash;
   }

Password Strength
-----------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\PasswordStrength;

   $score = (new PasswordStrength())->score('MyStrongPassword!2026');
   // 0..100

Master Secret + Wrapped Secret
------------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   $masterSecret = (new MasterSecretGenerator())->generate();

   $wrapped = (new WrappedSecretManager())->wrap('sensitive-secret', $masterSecret);
   $plain = (new WrappedSecretManager())->unwrap($wrapped, $masterSecret);

Wrapped secret format is versioned (``eps1.*``) and fail-closed on invalid input.

Wrapped Secret Rotation
-----------------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;
   use Infocyph\Epicrypt\Security\KeyRing;

   $manager = new WrappedSecretManager();
   $rotated = $manager->rewrap($wrapped, $oldMasterSecret, $newMasterSecret);

   $ring = new KeyRing(['old' => $oldMasterSecret, 'new' => $newMasterSecret], 'new');
   $result = $manager->unwrapWithAnyKeyResult($rotated, $ring);
   $plain = $result->plaintext;

Secure Secret Serialization
---------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\Secret\SecureSecretSerializer;

   $serializer = new SecureSecretSerializer();
   $encoded = $serializer->serialize(['api_key' => 'value']);
   $decoded = $serializer->unserialize($encoded);
