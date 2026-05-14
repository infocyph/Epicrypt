Quickstart
==========

.. code-block:: php

   <?php

   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->forSecretBox();
   $protector = new StringProtector();

   $ciphertext = $protector->encrypt('hello epicrypt', $key);
   $plaintext = $protector->decrypt($ciphertext, $key);

For deeper guides, see ``crypto.rst``, ``token.rst``, and ``data-protection.rst``.

