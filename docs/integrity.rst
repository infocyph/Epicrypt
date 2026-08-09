Integrity
=========

The curated allowlist is SHA-256, SHA-384, SHA-512, and BLAKE2b. SHA-256 is the
default. Use an unkeyed digest to identify public content and a keyed digest to
authenticate content from a party that shares the secret.

Complete path: publish and verify a signed release manifest
-----------------------------------------------------------

The publisher hashes the artifact with the streaming file API and signs the
exact manifest bytes. The deployment system verifies the signature before
trusting the digest, then verifies the artifact before installation.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\Signature;
   use Infocyph\Epicrypt\Integrity\FileHasher;
   use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;

   // Publisher side.
   $releaseKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $hasher = new FileHasher(IntegrityAlgorithm::SHA512);
   $manifest = json_encode([
       'artifact' => 'application-2.0.0.tar.gz',
       'sha512' => $hasher->hash('/srv/publish/application-2.0.0.tar.gz'),
   ], JSON_THROW_ON_ERROR);
   $signatures = new Signature();
   $manifestSignature = $signatures->sign($manifest, $releaseKeys['private']);

   // Deployment side: $releaseKeys['public'] must arrive through a trusted
   // configuration or pinning channel, not beside an untrusted download.
   if (!$signatures->verify($manifest, $manifestSignature, $releaseKeys['public'])) {
       throw new RuntimeException('Release manifest signature rejected.');
   }
   $trustedManifest = json_decode($manifest, true, flags: JSON_THROW_ON_ERROR);
   if (!is_string($trustedManifest['sha512'] ?? null)
       || !$hasher->verify(
           '/srv/downloads/application-2.0.0.tar.gz',
           $trustedManifest['sha512'],
       )) {
       throw new RuntimeException('Release artifact digest rejected.');
   }

   $installer->install('/srv/downloads/application-2.0.0.tar.gz');

Do not accept a digest delivered only with the artifact it is supposed to
authenticate. A digest detects change; the signature establishes who approved
that digest.

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
