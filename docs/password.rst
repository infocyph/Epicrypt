Password security
=================

``PasswordHasher`` defaults to Argon2id with validated platform defaults.
Argon2i remains available for compatible deployments. Bcrypt is available only
when explicitly selected for interoperability and rejects passwords longer
than 72 bytes. Algorithm and cost support are validated before hashing.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\PasswordHasher;

   $hasher = new PasswordHasher();
   $hash = $hasher->hashPassword($password);
   $result = $hasher->verifyAndNeedsRehash($password, $hash);

Generated passwords use ASCII character classes, so requested lengths are byte
lengths and the returned password is exactly that length. Impossible policies
are rejected before generation.
