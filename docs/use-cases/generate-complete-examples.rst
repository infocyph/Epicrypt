Generate Complete Examples
==========================

This page shows the ``Generate`` helpers in the same order they usually appear in real applications: random bytes first, then nonces, salts, keys, and token material.

Generate Random Bytes or Strings
--------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\RandomBytesGenerator;

   $random = new RandomBytesGenerator();
   $rawBytes = $random->bytes(32);
   $randomString = $random->string(48, 'tok_', '_v1');

Generate a Nonce
----------------

Use a nonce for encryption APIs that require one unique value per operation.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\NonceGenerator;

   $nonce = (new NonceGenerator())->generate(24, true);

Generate a Salt
---------------

Use a salt for password or key-derivation flows.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\SaltGenerator;

   $salt = (new SaltGenerator())->generate(16, true);

Generate Key Material
---------------------

Use this when a symmetric crypto API expects a key of a specific length.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $keyMaterial = (new KeyMaterialGenerator())->generate(32, true);

Generate Token Material
-----------------------

Use this when you need random token data before hashing or storing it.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;

   $tokenMaterial = (new TokenMaterialGenerator())->generate(48);
