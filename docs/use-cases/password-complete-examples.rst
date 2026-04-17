Password Complete Examples
==========================

This page groups ``Password`` examples by the job you are doing: generate a password, enforce policy, hash it, score it, or protect a stored secret.

Generate a Password
-------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;

   $password = (new PasswordGenerator())->generate(20, [
       'min_length' => 16,
       'require_upper' => true,
       'require_lower' => true,
       'require_digit' => true,
       'require_symbol' => true,
       'include_ambiguous' => false,
   ]);

Define a Password Policy
------------------------

Use this when the policy must be explicit and reusable.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;

   $policy = new PasswordPolicy(minLength: 12, requireUpper: true, requireLower: true, requireDigit: true, requireSymbol: true);

Hash and Verify a Password
--------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
   use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
   use Infocyph\Epicrypt\Password\PasswordHasher;

   $password = (new PasswordGenerator())->generate(20);
   $hasher = new PasswordHasher();
   $hash = $hasher->hashPassword($password, [
       'algorithm' => PasswordHashAlgorithm::ARGON2ID,
       'memory_cost' => 65536,
       'time_cost' => 4,
       'threads' => 2,
   ]);
   $passwordValid = $hasher->verifyPassword($password, $hash);

Score Password Strength
-----------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
   use Infocyph\Epicrypt\Password\PasswordStrength;

   $password = (new PasswordGenerator())->generate(20);
   $score = (new PasswordStrength())->score($password); // 0..100

Wrap and Unwrap a Secret
------------------------

Use this when an application secret must stay encrypted at rest.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   $masterSecret = (new MasterSecretGenerator())->generate(32, true);
   $wrappedManager = new WrappedSecretManager();
   $wrapped = $wrappedManager->wrap('db-password', $masterSecret);
   $plain = $wrappedManager->unwrap($wrapped, $masterSecret);

Serialize Secret Material
-------------------------

Use this when secret-bearing data needs a stable serialized representation before storage.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Secret\SecureSecretSerializer;

   $serializer = new SecureSecretSerializer();
   $serialized = $serializer->serialize(['username' => 'alice', 'password' => 'db-password']);
   $restored = $serializer->unserialize($serialized);
