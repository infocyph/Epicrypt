Generate Complete Examples
==========================

This page contains complete usage examples for ``Generate`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
   use Infocyph\Epicrypt\Generate\NonceGenerator;
   use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
   use Infocyph\Epicrypt\Generate\SaltGenerator;

   $random = new RandomBytesGenerator();
   $rawBytes = $random->bytes(32);
   $randomString = $random->string(48, 'tok_', '_v1');

   $nonce = (new NonceGenerator())->generate(24, true);
   $salt = (new SaltGenerator())->generate(16, true);
   $keyMaterial = (new KeyMaterialGenerator())->generate(32, true);
   $tokenMaterial = (new TokenMaterialGenerator())->generate(48);
