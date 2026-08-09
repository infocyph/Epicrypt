Password security
=================

``PasswordHasher`` defaults to Argon2id. Argon2i remains available for
compatible deployments; bcrypt is explicit-only and rejects passwords longer
than 72 bytes. Never encrypt passwords or use a fast general-purpose digest as
a password hash.

Complete path: register, authenticate, and upgrade credentials
--------------------------------------------------------------

The application validates policy and breach status at registration, stores only
the encoded Argon2id hash, and performs a compare-and-swap rehash after a
successful login. ``$compromisedPasswords`` implements
``CompromisedPasswordCheckerInterface`` and ``$users`` is the application
repository.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Password\PasswordPolicyValidator;

   $policy = new PasswordPolicy(minLength: 16, includeAmbiguous: true);
   $policyResult = new PasswordPolicyValidator()->validate(
       $registrationPassword,
       $policy,
   );
   if (!$policyResult->valid
       || $compromisedPasswords->isCompromised($registrationPassword)) {
       throw new DomainException('Password does not satisfy registration policy.');
   }

   $hasher = new PasswordHasher(); // Argon2id
   $users->create(
       $normalizedLogin,
       $hasher->hashPassword($registrationPassword),
   );

   // Later, on login, use one generic response for unknown users and bad hashes.
   $user = $users->findForAuthentication($normalizedLogin);
   $storedHash = $user?->passwordHash ?? $dummyArgon2idHash;
   $verification = $hasher->verifyAndRehash($loginPassword, $storedHash);
   if ($user === null || !$verification->verified) {
       throw new RuntimeException('Invalid credentials.');
   }
   if ($verification->rehashedHash !== null) {
       $users->replacePasswordHashIfCurrent(
           $user->id,
           $storedHash,
           $verification->rehashedHash,
       );
   }

   $sessions->rotateAfterAuthentication($user->id);

Provision ``$dummyArgon2idHash`` under the same deployment policy so the unknown
account path still performs password verification. Apply endpoint rate limits
and capacity-plan the intentional Argon2id cost; never reduce it merely to
increase login throughput.

Register, log in, and upgrade a stored hash
-------------------------------------------

On a successful login, ``verifyAndRehash()`` can migrate an older supported
hash to the current Argon2id policy without forcing a password reset.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\PasswordHasher;

   $hasher = new PasswordHasher(); // Argon2id

   // Registration: store this encoded hash, never the password.
   $storedHash = $hasher->hashPassword($submittedPassword);

   // Login: update the database only after successful verification.
   $verification = $hasher->verifyAndRehash($submittedPassword, $storedHash);
   if (!$verification->verified) {
       throw new RuntimeException('Invalid credentials.');
   }
   if ($verification->rehashedHash !== null) {
       $users->replacePasswordHash($userId, $verification->rehashedHash);
   }

Validate or generate a password
-------------------------------

Policy validation reports machine-readable violations and a strength score.
Generated passwords satisfy the selected ASCII character-class policy exactly.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
   use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
   use Infocyph\Epicrypt\Password\PasswordPolicyValidator;

   $policy = new PasswordPolicy(minLength: 16, includeAmbiguous: false);
   $validation = new PasswordPolicyValidator()->validate($submittedPassword, $policy);
   if (!$validation->valid) {
       throw new DomainException(implode(', ', $validation->violations));
   }

   $serviceAccountPassword = new PasswordGenerator()->generate(24, $policy);

Protect a recoverable application secret
----------------------------------------

Passwords are one-way hashes, but API credentials sometimes must be recovered.
Wrap those secrets under a generated master secret and keep the master secret
in a secret manager, separate from the database.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
   use Infocyph\Epicrypt\Password\Secret\SecureSecretSerializer;
   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   $masterSecret = new MasterSecretGenerator()->generate();
   $serializer = new SecureSecretSerializer();
   $manager = new WrappedSecretManager();

   $serialized = $serializer->serialize([
       'provider' => 'payments',
       'api_key' => $providerApiKey,
   ]);
   $wrapped = $manager->wrap($serialized, $masterSecret);

   $secret = $serializer->unserialize($manager->unwrap($wrapped, $masterSecret));

Use ``KeyRing`` with ``KeyPurpose::SECRET_WRAPPING`` for managed master-secret
rotation.

Explicit algorithm selection
----------------------------

Argon2id is the recommended default. Select Argon2i or bcrypt only for a
specific compatibility requirement and retain the default cost validation.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Password\PasswordHashOptions;

   $legacyBcrypt = new PasswordHasher(new PasswordHashOptions(
       algorithm: PasswordHashAlgorithm::BCRYPT,
       bcryptCost: 12,
   ));

Use the default Argon2id hasher as the target of ``verifyAndRehash()`` to move
accounts away from a compatible legacy hash after a successful login.
