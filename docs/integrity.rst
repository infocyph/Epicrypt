Integrity Domain
================

Namespace: ``Infocyph\\Epicrypt\\Integrity``

Scope
-----

- string hashing
- file hashing
- digest verification
- timing-safe comparison support
- content fingerprint support

String Hashing
--------------

.. code-block:: php

   use Infocyph\Epicrypt\Integrity\StringHasher;

   $hasher = new StringHasher('sha256');
   $digest = $hasher->hash('payload');
   $isValid = $hasher->verify('payload', $digest);

HMAC
~~~~

.. code-block:: php

   $digest = $hasher->hash('payload', ['key' => 'hmac-secret']);

Blake2b
~~~~~~~

.. code-block:: php

   $blake = new StringHasher('blake2b');
   $digest = $blake->hash('payload', ['length' => 32]);

File Hashing
------------

.. code-block:: php

   use Infocyph\Epicrypt\Integrity\FileHasher;

   $fileHasher = new FileHasher('sha256');
   $digest = $fileHasher->hash('/path/to/file.txt');
   $isValid = $fileHasher->verify('/path/to/file.txt', $digest);
