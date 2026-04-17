Password Complete Examples
==========================

This page contains complete usage examples for ``Password`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
   use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Password\PasswordStrength;
   use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
   use Infocyph\Epicrypt\Password\Secret\SecureSecretSerializer;
   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   // PasswordGenerator options
   $password = (new PasswordGenerator())->generate(20, [
       'min_length' => 16,
       'require_upper' => true,
       'require_lower' => true,
       'require_digit' => true,
       'require_symbol' => true,
       'include_ambiguous' => false,
   ]);

   // PasswordPolicy value object
   $policy = new PasswordPolicy(minLength: 12, requireUpper: true, requireLower: true, requireDigit: true, requireSymbol: true);

   // PasswordHasher
   $hasher = new PasswordHasher();
   $hash = $hasher->hashPassword($password, [
       'algorithm' => PasswordHashAlgorithm::ARGON2ID,
       'memory_cost' => 65536,
       'time_cost' => 4,
       'threads' => 2,
   ]);
   $passwordValid = $hasher->verifyPassword($password, $hash);

   // PasswordStrength
   $score = (new PasswordStrength())->score($password); // 0..100

   // Secret helpers
   $masterSecret = (new MasterSecretGenerator())->generate(32, true);
   $wrappedManager = new WrappedSecretManager();
   $wrapped = $wrappedManager->wrap('db-password', $masterSecret);
   $plain = $wrappedManager->unwrap($wrapped, $masterSecret);

   $serializer = new SecureSecretSerializer();
   $serialized = $serializer->serialize(['username' => 'alice', 'password' => 'db-password']);
   $restored = $serializer->unserialize($serialized);
