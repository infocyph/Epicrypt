Integrity Complete Examples
===========================

This page contains complete usage examples for ``Integrity`` APIs.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\FileHasher;
   use Infocyph\Epicrypt\Integrity\StringHasher;
   use Infocyph\Epicrypt\Integrity\Support\ContentFingerprinter;
   use Infocyph\Epicrypt\Integrity\Support\TimingSafeComparator;

   // StringHasher
   $stringHasher = new StringHasher('sha256');
   $digest = $stringHasher->hash('payload');
   $digestValid = $stringHasher->verify('payload', $digest);

   // StringHasher with HMAC
   $hmac = $stringHasher->hash('payload', ['key' => 'shared-secret']);

   // StringHasher with Blake2b
   $blake = (new StringHasher('blake2b'))->hash('payload', ['length' => 32]);

   // FileHasher
   $fileHasher = new FileHasher('sha256');
   $fileDigest = $fileHasher->hash('/tmp/payload.txt');
   $fileDigestValid = $fileHasher->verify('/tmp/payload.txt', $fileDigest);

   // FileHasher with keyed hashing
   $fileHmac = $fileHasher->hash('/tmp/payload.txt', 'shared-secret');

   // Support helpers
   $fingerprint = (new ContentFingerprinter())->fingerprint('payload', ['a' => '1', 'b' => '2']);
   $same = (new TimingSafeComparator())->equals('known', 'known');
