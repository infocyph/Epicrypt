Passwords
=========

Canonical capability guide for password and secret protection APIs.

For full domain-level reference and more examples, see :doc:`password`.

Key components:

- ``PasswordHasher`` for hash/verify/rehash lifecycle.
- ``PasswordPolicyValidator`` for policy enforcement results.
- ``PasswordStrength`` for lightweight scoring with repetition/sequence/common-pattern penalties.
- ``CompromisedPasswordCheckerInterface`` for pluggable breach checks.
- ``WrappedSecretManager`` for encrypted secret wrapping and key-rotation aware unwrapping.

Quick Example
-------------

.. code-block:: php

   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Password\PasswordPolicyValidator;
   use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;

   $hasher = new PasswordHasher();
   $hash = $hasher->hashPassword('MyStrongPassword!2026');
   $verified = $hasher->verifyPassword('MyStrongPassword!2026', $hash);

   $policy = new PasswordPolicy(minLength: 12, requireUpper: true, requireLower: true, requireDigit: true, requireSymbol: true);
   $policyResult = (new PasswordPolicyValidator())->validate('MyStrongPassword!2026', $policy);
