Integrity
=========

The curated allowlist is SHA-256, SHA-384, SHA-512, and BLAKE2b. SHA-256 is the
default. Use an unkeyed digest to identify public content and a keyed digest to
authenticate content from a party that shares the secret.

Verify a downloaded release artifact
-------------------------------------

Publish the expected digest over a separately authenticated channel, then
verify the downloaded file before installing it.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\FileHasher;
   use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;

   $artifact = '/srv/releases/application.tar.gz';
   $expectedDigest = $_ENV['RELEASE_SHA512'];
   $hasher = new FileHasher(IntegrityAlgorithm::SHA512);

   if (!$hasher->verify($artifact, $expectedDigest)) {
       throw new RuntimeException('Release artifact integrity check failed.');
   }

Authenticate a webhook body
---------------------------

Do not parse and re-encode the body before verification: authenticate the exact
bytes received from the transport.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;
   use Infocyph\Epicrypt\Integrity\StringHasher;

   $rawBody = (string) file_get_contents('php://input');
   $providedDigest = (string) ($_SERVER['HTTP_X_BODY_DIGEST'] ?? '');
   $webhookKey = $_ENV['WEBHOOK_INTEGRITY_KEY'];
   $hasher = new StringHasher(IntegrityAlgorithm::SHA256);

   if (!$hasher->verify($rawBody, $providedDigest, ['key' => $webhookKey])) {
       throw new RuntimeException('Webhook authentication failed.');
   }

For a new application protocol, prefer ``Crypto\Mac`` when you do not need an
existing hexadecimal digest format.
