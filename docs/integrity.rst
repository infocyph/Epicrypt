Integrity
=========

Security-facing hashing accepts only SHA-256, SHA-384, SHA-512, and BLAKE2b.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;
   use Infocyph\Epicrypt\Integrity\StringHasher;

   $hasher = new StringHasher(IntegrityAlgorithm::SHA512);
   $digest = $hasher->hash('content');
   $valid = $hasher->verify('content', $digest);

Use a non-empty key option when message authentication rather than an unkeyed
digest is required.
