Integrity Complete Examples
===========================

This page groups ``Integrity`` examples by what is being checked: strings, files, and support helpers.

Hash and Verify a String
------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\StringHasher;

   $stringHasher = new StringHasher('sha256');
   $digest = $stringHasher->hash('payload');
   $digestValid = $stringHasher->verify('payload', $digest);

Hash with a Shared Secret
-------------------------

Use this when a digest must also prove knowledge of a secret.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\StringHasher;

   $stringHasher = new StringHasher('sha256');
   $hmac = $stringHasher->hash('payload', ['key' => 'shared-secret']);

Use an Alternate Algorithm
--------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\StringHasher;

   $blake = (new StringHasher('blake2b'))->hash('payload', ['length' => 32]);

Hash and Verify a File
----------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\FileHasher;

   $fileHasher = new FileHasher('sha256');
   $fileDigest = $fileHasher->hash('/tmp/payload.txt');
   $fileDigestValid = $fileHasher->verify('/tmp/payload.txt', $fileDigest);

Hash a File with a Shared Secret
--------------------------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\FileHasher;

   $fileHasher = new FileHasher('sha256');
   $fileHmac = $fileHasher->hash('/tmp/payload.txt', 'shared-secret');

Use Support Helpers
-------------------

Use helpers for canonical fingerprints and timing-safe equality checks.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\Support\ContentFingerprinter;
   use Infocyph\Epicrypt\Integrity\Support\TimingSafeComparator;

   $fingerprint = (new ContentFingerprinter())->fingerprint('payload', ['a' => '1', 'b' => '2']);
   $same = (new TimingSafeComparator())->equals('known', 'known');
