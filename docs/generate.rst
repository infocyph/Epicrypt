Secure generation
=================

Epicrypt generation services use cryptographically secure operating-system
randomness. Generate keys at their algorithm-required length and store them in a
secret manager.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $generator = new KeyMaterialGenerator();
   $encodedKey = $generator->forAead();

Key derivation APIs require explicit context objects for related options. Use a
unique non-empty HKDF ``info`` value for every application purpose.
