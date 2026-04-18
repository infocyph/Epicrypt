Generate Domain
===============

Namespace: ``Infocyph\\Epicrypt\\Generate``

Scope
-----

- random bytes
- random strings
- nonces
- salts
- key material
- derived key material
- token material

Random Bytes and Strings
------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Generate\RandomBytesGenerator;

   $random = new RandomBytesGenerator();
   $bytes = $random->bytes(32);
   $string = $random->string(40, prefix: 'ep_', postfix: '_v1');

Nonce and Salt
--------------

.. code-block:: php

   use Infocyph\Epicrypt\Generate\NonceGenerator;
   use Infocyph\Epicrypt\Generate\SaltGenerator;

   $nonce = (new NonceGenerator())->generate();
   $salt = (new SaltGenerator())->generate();

Key and Token Material
----------------------

.. code-block:: php

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;

   $keyMaterial = (new KeyMaterialGenerator())->generate(32); // Base64URL by default
   $tokenMaterial = (new TokenMaterialGenerator())->generate(48);

Purpose-Aware Key Material
--------------------------

.. code-block:: php

   use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

   $generator = new KeyMaterialGenerator();
   $aeadKey = $generator->forPurpose(KeyPurpose::AEAD, SecurityProfile::MODERN);
   $masterSecret = $generator->forMasterSecret();

Key Derivation
--------------

.. code-block:: php

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;

   $deriver = new KeyDeriver();
   $hkdfKey = $deriver->hkdf($inputKeyMaterial, 32, [
       'info' => 'app:encryption',
       'salt' => $salt,
   ]);

   $passwordKey = $deriver->deriveFromPassword('password', $salt, 32);
   $subkey = $deriver->subkey($rootKey, 1, 32, ['context' => 'EPCKDF01']);
